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
# 1. Detects osqueryd (checks PATH and common install locations)
# 2. If osqueryd not found, falls back to running tests in Docker
# 3. Builds extension examples (logger-file, config-static)
# 4. Sets up autoload configuration
# 5. Starts osqueryd with extensions autoloaded
# 6. Waits for socket AND extensions to be ready
# 7. Runs integration tests with osquery-tests feature
# 8. Optionally generates coverage reports
# 9. Cleans up on exit (success or failure)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CI_DIR="/tmp/osquery-ci-$$"
OSQUERY_PID=""
COVERAGE=false
HTML=false
DOCKER_IMAGE="osquery-rust-test:latest"

# Parse args
for arg in "$@"; do
    case $arg in
        --coverage) COVERAGE=true ;;
        --html) HTML=true ;;
    esac
done

cleanup() {
    echo "Cleaning up..."
    # Kill osqueryd by name since piping to tee makes $! capture tee's PID
    pkill -f "osqueryd.*extensions_socket.*$CI_DIR" 2>/dev/null || true
    if [ -n "$OSQUERY_PID" ]; then
        kill "$OSQUERY_PID" 2>/dev/null || true
        wait "$OSQUERY_PID" 2>/dev/null || true
    fi
    # Give osqueryd a moment to exit
    sleep 1
    rm -rf "$CI_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Find osqueryd binary - check PATH and common install locations
find_osqueryd() {
    # Check PATH first
    if command -v osqueryd &> /dev/null; then
        command -v osqueryd
        return 0
    fi

    # Common installation paths
    local paths=(
        "/opt/osquery/bin/osqueryd"        # Linux .deb/.rpm package
        "/usr/local/bin/osqueryd"          # Manual install / homebrew
        "/usr/bin/osqueryd"                # System package
    )

    for path in "${paths[@]}"; do
        if [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done

    return 1
}

# Check if Docker is available
has_docker() {
    command -v docker &> /dev/null && docker info &> /dev/null
}

# Build Docker test image if needed
build_docker_image() {
    echo "Building Docker test image..."
    cd "$PROJECT_ROOT"
    docker build -t "$DOCKER_IMAGE" -f docker/Dockerfile.test .
}

# Run tests inside Docker container
run_tests_in_docker() {
    echo "=== Running tests in Docker ==="

    # Build the image first
    build_docker_image

    local docker_args=(
        "--rm"
        "-v" "$PROJECT_ROOT:/workspace"
        "-w" "/workspace"
        "-e" "CARGO_HOME=/workspace/.cargo-docker"
    )

    # Set up environment for coverage
    if [ "$COVERAGE" = true ]; then
        docker_args+=("-e" "RUSTFLAGS=-C instrument-coverage")
    fi

    # The entrypoint script handles starting osqueryd and running tests
    local test_script='
set -e

# Set up paths - use standard /var/osquery path that extensions default to
CI_DIR="/var/osquery"
mkdir -p "$CI_DIR"/{extensions,db,logs}
chmod 777 "$CI_DIR" "$CI_DIR/extensions" "$CI_DIR/db" "$CI_DIR/logs"

SOCKET_PATH="$CI_DIR/osquery.em"
EXTENSIONS_DIR="$CI_DIR/extensions"
DB_PATH="$CI_DIR/db"
LOGGER_FILE="$CI_DIR/logs/file_logger.log"
CONFIG_MARKER="$CI_DIR/logs/config_marker.txt"

# Set environment for logger and config plugins
export FILE_LOGGER_PATH="$LOGGER_FILE"
export CONFIG_MARKER_PATH="$CONFIG_MARKER"

# Copy pre-built extensions from image
cp /opt/osquery/extensions/logger-file.ext "$EXTENSIONS_DIR/"
cp /opt/osquery/extensions/config-static.ext "$EXTENSIONS_DIR/"
chmod +x "$EXTENSIONS_DIR"/*.ext

# Create extensions.load
cat > "$CI_DIR/extensions.load" << EXTEOF
$EXTENSIONS_DIR/logger-file.ext
$EXTENSIONS_DIR/config-static.ext
EXTEOF

echo "Starting osqueryd..."
/opt/osquery/bin/osqueryd \
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

# Wait for socket
echo "Waiting for osquery socket..."
for i in {1..30}; do
    if [ -S "$SOCKET_PATH" ]; then
        echo "Socket ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Socket not ready"
        cat "$CI_DIR/osqueryd.log"
        exit 1
    fi
    sleep 1
done

# Wait for extensions
echo "Waiting for extensions..."
for i in {1..30}; do
    EXTENSIONS=$(osqueryi --socket "$SOCKET_PATH" --json \
        "SELECT name FROM osquery_extensions WHERE name IN ('"'"'file_logger'"'"', '"'"'static_config'"'"')" 2>/dev/null || echo "[]")

    LOGGER_READY=$(echo "$EXTENSIONS" | grep -c "file_logger" || true)
    CONFIG_READY=$(echo "$EXTENSIONS" | grep -c "static_config" || true)

    if [ "$LOGGER_READY" -ge 1 ] && [ "$CONFIG_READY" -ge 1 ]; then
        echo "Extensions registered"
        break
    fi

    if [ "$i" -eq 30 ]; then
        echo "ERROR: Extensions not registered"
        osqueryi --socket "$SOCKET_PATH" "SELECT * FROM osquery_extensions" 2>/dev/null || true
        cat "$CI_DIR/osqueryd.log"
        exit 1
    fi
    sleep 1
done

# Wait for first snapshot
echo "Waiting for first scheduled query..."
for i in {1..15}; do
    if [ -f "$LOGGER_FILE" ] && grep -q "SNAPSHOT" "$LOGGER_FILE" 2>/dev/null; then
        echo "First snapshot logged"
        break
    fi
    if [ "$i" -eq 15 ]; then
        echo "Warning: No snapshot after 15s"
    fi
    sleep 1
done

# Export for tests
export OSQUERY_SOCKET="$SOCKET_PATH"
export TEST_LOGGER_FILE="$LOGGER_FILE"
export TEST_CONFIG_MARKER_FILE="$CONFIG_MARKER"

echo ""
echo "=== Running tests ==="
echo "OSQUERY_SOCKET=$OSQUERY_SOCKET"
echo "TEST_LOGGER_FILE=$TEST_LOGGER_FILE"
echo "TEST_CONFIG_MARKER_FILE=$TEST_CONFIG_MARKER_FILE"
echo ""
'

    if [ "$COVERAGE" = true ]; then
        if [ "$HTML" = true ]; then
            test_script+='cargo llvm-cov --all-features --workspace --html --ignore-filename-regex "_osquery"'
        else
            test_script+='cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info --ignore-filename-regex "_osquery"'
        fi
    else
        test_script+='cargo test --all-features --workspace'
    fi

    test_script+='
RESULT=$?

# Cleanup - use pkill since tee pipe makes $! capture tee PID, not osqueryd
pkill -f "osqueryd.*extensions_socket" 2>/dev/null || true
kill $OSQUERY_PID 2>/dev/null || true
sleep 1
exit $RESULT
'

    docker run "${docker_args[@]}" "$DOCKER_IMAGE" /bin/bash -c "$test_script"

    # Copy coverage output if generated
    if [ "$COVERAGE" = true ] && [ -f "$PROJECT_ROOT/lcov.info" ]; then
        # Calculate coverage percentage (cross-platform: use awk instead of paste)
        if [ -f "$PROJECT_ROOT/lcov.info" ]; then
            LINES_HIT=$(grep -E "^LH:" "$PROJECT_ROOT/lcov.info" | cut -d: -f2 | awk '{sum+=$1} END {print sum}' 2>/dev/null || echo 0)
            LINES_FOUND=$(grep -E "^LF:" "$PROJECT_ROOT/lcov.info" | cut -d: -f2 | awk '{sum+=$1} END {print sum}' 2>/dev/null || echo 1)
            if [ -n "$LINES_HIT" ] && [ -n "$LINES_FOUND" ] && [ "$LINES_FOUND" -gt 0 ]; then
                COVERAGE_PCT=$(awk "BEGIN {printf \"%.1f\", $LINES_HIT * 100 / $LINES_FOUND}")
            else
                COVERAGE_PCT="0"
            fi
            echo "Coverage: $COVERAGE_PCT%"
            echo "coverage=$COVERAGE_PCT" >> "${GITHUB_OUTPUT:-/dev/null}"
        fi
    fi
}

# ========== MAIN ==========

OSQUERYD_PATH=""
if OSQUERYD_PATH=$(find_osqueryd); then
    echo "Found osqueryd at: $OSQUERYD_PATH"
else
    echo "osqueryd not found in PATH or common locations"

    if has_docker; then
        echo "Docker available - will run tests in Docker container"
        run_tests_in_docker
        exit 0
    else
        echo "ERROR: Neither osqueryd nor Docker available"
        echo ""
        echo "To run tests, either:"
        echo "  1. Install osquery: https://osquery.io/downloads"
        echo "  2. Install Docker and run: ./scripts/ci-test.sh"
        exit 1
    fi
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
$OSQUERYD_PATH \
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

echo ""
echo "=== Running tests ==="
echo "OSQUERY_SOCKET=$OSQUERY_SOCKET"
echo "TEST_LOGGER_FILE=$TEST_LOGGER_FILE"
echo "TEST_CONFIG_MARKER_FILE=$TEST_CONFIG_MARKER_FILE"
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

        # Calculate and display coverage (cross-platform: use awk instead of paste/bc)
        if [ -f lcov.info ]; then
            LINES_HIT=$(grep -E "^LH:" lcov.info | cut -d: -f2 | awk '{sum+=$1} END {print sum}')
            LINES_FOUND=$(grep -E "^LF:" lcov.info | cut -d: -f2 | awk '{sum+=$1} END {print sum}')
            if [ -n "$LINES_HIT" ] && [ -n "$LINES_FOUND" ] && [ "$LINES_FOUND" -gt 0 ]; then
                COVERAGE_PCT=$(awk "BEGIN {printf \"%.1f\", $LINES_HIT * 100 / $LINES_FOUND}")
            else
                COVERAGE_PCT="0"
            fi
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
