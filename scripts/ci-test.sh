#!/usr/bin/env bash
# CI Test Runner for osquery-rust
#
# Usage: ./scripts/ci-test.sh [--coverage] [--html]
#
# Options:
#   --coverage  Generate lcov coverage report
#   --html      Generate HTML coverage report
#
# This script:
# 1. Builds extension examples (logger-file, config-static)
# 2. Sets up autoload configuration
# 3. Starts osqueryd with extensions autoloaded
# 4. Waits for socket AND extensions to be ready
# 5. Runs integration tests with osquery-tests feature
# 6. Optionally generates coverage reports
# 7. Cleans up on exit (success or failure)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CI_DIR="/tmp/osquery-ci-$$"
OSQUERY_PID=""
COVERAGE=false
HTML=false

# Parse args
for arg in "$@"; do
    case $arg in
        --coverage) COVERAGE=true ;;
        --html) HTML=true ;;
    esac
done

cleanup() {
    echo "Cleaning up..."
    if [ -n "$OSQUERY_PID" ]; then
        kill "$OSQUERY_PID" 2>/dev/null || true
        wait "$OSQUERY_PID" 2>/dev/null || true
    fi
    rm -rf "$CI_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Detect osquery binaries
USE_DAEMON=false
if command -v osqueryd &> /dev/null; then
    USE_DAEMON=true
    echo "Found osqueryd - will use daemon mode with autoload"
elif command -v osqueryi &> /dev/null; then
    echo "WARNING: osqueryd not found, only osqueryi available"
    echo "Autoload tests will be skipped. Install full osquery package for complete testing."
    echo "https://osquery.io/downloads"
else
    echo "ERROR: Neither osqueryd nor osqueryi found in PATH"
    echo "Install osquery: https://osquery.io/downloads"
    exit 1
fi

echo "=== Setting up CI test environment ==="

# Create CI directory structure
mkdir -p "$CI_DIR"/{extensions,db,logs}
chmod 777 "$CI_DIR" "$CI_DIR/extensions" "$CI_DIR/db" "$CI_DIR/logs"

SOCKET_PATH="$CI_DIR/osquery.em"
EXTENSIONS_DIR="$CI_DIR/extensions"
DB_PATH="$CI_DIR/db"
LOGGER_FILE="$CI_DIR/logs/file_logger.log"
CONFIG_MARKER="$CI_DIR/logs/config_marker.txt"

cd "$PROJECT_ROOT"

if [ "$USE_DAEMON" = true ]; then
    # ========== FULL DAEMON MODE WITH AUTOLOAD ==========
    # Set environment variables for extensions BEFORE building
    export FILE_LOGGER_PATH="$LOGGER_FILE"
    export CONFIG_MARKER_PATH="$CONFIG_MARKER"

    echo "Building extensions..."
    cargo build --workspace 2>&1 | tail -5

    # Copy extensions to autoload directory with .ext suffix
    echo "Setting up extension autoload..."
    if [ -f target/debug/logger-file ]; then
        cp target/debug/logger-file "$EXTENSIONS_DIR/logger-file.ext"
    else
        cp target/release/logger-file "$EXTENSIONS_DIR/logger-file.ext"
    fi
    if [ -f target/debug/config_static ]; then
        cp target/debug/config_static "$EXTENSIONS_DIR/config-static.ext"
    else
        cp target/release/config_static "$EXTENSIONS_DIR/config-static.ext"
    fi
    chmod +x "$EXTENSIONS_DIR"/*.ext

    # Create extensions.load file
    cat > "$CI_DIR/extensions.load" << EOF
$EXTENSIONS_DIR/logger-file.ext
$EXTENSIONS_DIR/config-static.ext
EOF

    echo "Extensions configured:"
    cat "$CI_DIR/extensions.load"

    echo "Starting osqueryd..."
    # Start osqueryd with extension autoloading
    # Key flags:
    # --ephemeral: Don't persist RocksDB data
    # --disable_watchdog: Don't restart crashed extensions
    # --extensions_timeout: Wait longer for extensions to register
    # --extensions_interval: Check for extensions more frequently
    # --force: Run without root privileges
    osqueryd \
        --ephemeral \
        --force \
        --disable_watchdog \
        --disable_extensions=false \
        --extensions_socket="$SOCKET_PATH" \
        --extensions_autoload="$CI_DIR/extensions.load" \
        --extensions_timeout=30 \
        --extensions_interval=1 \
        --database_path="$DB_PATH" \
        --config_plugin=static_config \
        --logger_plugin=file_logger \
        --verbose \
        2>&1 | tee "$CI_DIR/osqueryd.log" &
    OSQUERY_PID=$!

    echo "osqueryd PID: $OSQUERY_PID"

    # Wait for socket with timeout
    echo "Waiting for osquery socket..."
    for i in {1..30}; do
        if [ -S "$SOCKET_PATH" ]; then
            echo "Socket ready at $SOCKET_PATH"
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo "ERROR: Socket not ready after 30s"
            echo "osqueryd log:"
            cat "$CI_DIR/osqueryd.log"
            exit 1
        fi
        sleep 1
    done

    # Wait for extensions to register
    echo "Waiting for extensions to register..."
    for i in {1..30}; do
        # Check if both extensions are registered
        EXTENSIONS=$(osqueryi --socket "$SOCKET_PATH" --json \
            "SELECT name FROM osquery_extensions WHERE name IN ('file_logger', 'static_config')" 2>/dev/null || echo "[]")

        LOGGER_READY=$(echo "$EXTENSIONS" | grep -c "file_logger" || true)
        CONFIG_READY=$(echo "$EXTENSIONS" | grep -c "static_config" || true)

        if [ "$LOGGER_READY" -ge 1 ] && [ "$CONFIG_READY" -ge 1 ]; then
            echo "Extensions registered successfully"
            break
        fi

        if [ "$i" -eq 30 ]; then
            echo "ERROR: Extensions not registered after 30s"
            echo "Registered extensions:"
            osqueryi --socket "$SOCKET_PATH" "SELECT * FROM osquery_extensions" 2>/dev/null || true
            echo "osqueryd log:"
            cat "$CI_DIR/osqueryd.log"
            exit 1
        fi
        sleep 1
    done

    # Wait for first scheduled query to run (generates snapshots)
    echo "Waiting for first scheduled query..."
    for i in {1..15}; do
        if [ -f "$LOGGER_FILE" ] && grep -q "SNAPSHOT" "$LOGGER_FILE" 2>/dev/null; then
            echo "First snapshot logged"
            break
        fi
        if [ "$i" -eq 15 ]; then
            echo "Warning: No snapshot after 15s, continuing anyway"
        fi
        sleep 1
    done

    # Show what was logged
    echo "Logger file contents:"
    cat "$LOGGER_FILE" 2>/dev/null || echo "(empty)"

    echo "Config marker contents:"
    cat "$CONFIG_MARKER" 2>/dev/null || echo "(empty)"

    # Export for tests
    export OSQUERY_SOCKET="$SOCKET_PATH"
    export TEST_LOGGER_FILE="$LOGGER_FILE"
    export TEST_CONFIG_MARKER_FILE="$CONFIG_MARKER"

else
    # ========== SIMPLE OSQUERYI MODE (limited tests) ==========
    echo "Using osqueryi (limited mode - autoload tests will fail)"

    # Start osqueryi in background
    (while true; do sleep 60; done | osqueryi \
        --nodisable_extensions \
        --extensions_socket="$SOCKET_PATH" 2>/dev/null) &
    OSQUERY_PID=$!

    echo "osqueryi PID: $OSQUERY_PID"

    # Wait for socket with timeout
    echo "Waiting for osquery socket..."
    for i in {1..30}; do
        if [ -S "$SOCKET_PATH" ]; then
            echo "Socket ready at $SOCKET_PATH"
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo "ERROR: Socket not ready after 30s"
            exit 1
        fi
        sleep 1
    done

    # Export only socket - autoload env vars NOT set (tests will panic)
    export OSQUERY_SOCKET="$SOCKET_PATH"
    echo ""
    echo "NOTE: Running in osqueryi mode - autoload-dependent tests will fail."
    echo "Install osqueryd for full test coverage."
fi

echo ""
echo "=== Running tests ==="
echo "OSQUERY_SOCKET=$OSQUERY_SOCKET"
echo "TEST_LOGGER_FILE=${TEST_LOGGER_FILE:-<not set>}"
echo "TEST_CONFIG_MARKER_FILE=${TEST_CONFIG_MARKER_FILE:-<not set>}"
echo ""

cd "$PROJECT_ROOT"
if [ "$COVERAGE" = true ]; then
    if [ "$HTML" = true ]; then
        cargo llvm-cov --all-features --workspace --html \
            --ignore-filename-regex "_osquery"
        echo "HTML report: target/llvm-cov/html/index.html"
    else
        cargo llvm-cov --all-features --workspace --lcov \
            --output-path lcov.info --ignore-filename-regex "_osquery"

        # Calculate and display coverage
        if [ -f lcov.info ]; then
            LINES_HIT=$(grep -E "^LH:" lcov.info | cut -d: -f2 | paste -sd+ | bc || echo 0)
            LINES_FOUND=$(grep -E "^LF:" lcov.info | cut -d: -f2 | paste -sd+ | bc || echo 1)
            COVERAGE_PCT=$(echo "scale=1; $LINES_HIT * 100 / $LINES_FOUND" | bc)
            echo "Coverage: $COVERAGE_PCT%"
            # Output for GitHub Actions
            echo "coverage=$COVERAGE_PCT" >> "${GITHUB_OUTPUT:-/dev/null}"
        fi
    fi
else
    cargo test --all-features --workspace
fi

echo ""
echo "=== Tests completed successfully ==="
