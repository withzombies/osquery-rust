#!/usr/bin/env bash
set -euo pipefail

# Coverage script with osquery for integration tests and examples
# Usage: ./scripts/coverage.sh [--html] [--examples-only]
#
# This script mirrors the pre-commit hook workflow, running all tests including
# the autoloaded logger integration test.
#
# Options:
#   --html          Generate HTML coverage report
#   --examples-only Only test examples, skip coverage
#
# Platform handling:
# - Uses local osqueryd if available (required for autoload tests)
# - Falls back to Docker on amd64 only (osquery image is amd64-only)

OSQUERY_IMAGE="osquery/osquery:5.17.0-ubuntu22.04"
SOCKET_DIR="/tmp/osquery-coverage-$$"
CONTAINER_NAME="osquery-coverage-$$"
OSQUERY_PID=""
USE_DOCKER=false
EXAMPLES_ONLY=false
HTML_REPORT=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --html)
            HTML_REPORT=true
            ;;
        --examples-only)
            EXAMPLES_ONLY=true
            ;;
    esac
done

# Test a table plugin example - load extension and query the table
# Args: $1=binary_name $2=table_name
test_table_example() {
    local binary="$1"
    local table="$2"

    echo -n "  $binary ($table)... "

    # Retry up to 3 times (race condition between extension load and query)
    for attempt in 1 2 3; do
        local output
        output=$(osqueryi --extension "./target/debug/$binary" \
            --line "SELECT * FROM $table LIMIT 1;" 2>&1)

        # Check for success (has output and no "no such table" error)
        if [ -n "$output" ] && ! echo "$output" | grep -q "no such table"; then
            echo "OK"
            return 0
        fi
        sleep 1
    done

    echo "FAILED"
    return 1
}

# Test a config/logger plugin example - verify it registers
# Args: $1=binary_name $2=expected_extension_name
test_plugin_example() {
    local binary="$1"
    local expected_name="$2"

    echo -n "  $binary ($expected_name)... "

    for attempt in 1 2 3; do
        local output
        output=$(osqueryi --extension "./target/debug/$binary" \
            --line "SELECT name FROM osquery_extensions WHERE name = '$expected_name';" 2>&1)

        if echo "$output" | grep -q "$expected_name"; then
            echo "OK"
            return 0
        fi
        sleep 1
    done

    echo "FAILED"
    return 1
}

# Test all examples that work on the current platform
test_examples() {
    echo "Testing example extensions..."

    local failed=0
    local platform
    platform=$(uname -s)

    # Build examples first
    echo "  Building workspace..."
    if ! cargo build --workspace 2>/dev/null; then
        echo "  FAILED to build workspace"
        return 1
    fi
    echo "  Build complete."

    # Table plugins - query actual tables
    test_table_example "two-tables" "t1" || ((failed++))
    test_table_example "writeable-table" "writeable_table" || ((failed++))

    # Config plugins - verify registration
    test_plugin_example "config_static" "static_config" || ((failed++))
    test_plugin_example "config_file" "file_config" || ((failed++))

    # Logger plugins - verify registration
    test_plugin_example "logger-file" "file_logger" || ((failed++))
    test_plugin_example "logger-syslog" "syslog_logger" || ((failed++))

    # Linux-only: table-proc-meminfo (reads /proc/meminfo)
    if [ "$platform" = "Linux" ]; then
        test_table_example "table-proc-meminfo" "proc_meminfo" || ((failed++))
    else
        echo "  Skipping table-proc-meminfo (Linux only)"
    fi

    if [ "$failed" -gt 0 ]; then
        echo "Example tests: $failed failed"
        return 1
    fi

    echo "Example tests: all passed"
    return 0
}

cleanup() {
    # Suppress "Terminated" messages from killed background jobs
    set +e
    if [ "$USE_DOCKER" = true ]; then
        docker stop "$CONTAINER_NAME" 2>/dev/null
        docker rm "$CONTAINER_NAME" 2>/dev/null
    elif [ -n "$OSQUERY_PID" ]; then
        kill "$OSQUERY_PID" 2>/dev/null
        wait "$OSQUERY_PID" 2>/dev/null
    fi
    # Kill any extension processes
    pkill -f "logger-file.*$SOCKET_DIR" 2>/dev/null || true
    rm -rf "$SOCKET_DIR" 2>/dev/null
    set -e
}

trap cleanup EXIT

# Find osqueryd - check common locations (macOS app bundle, Linux, PATH)
find_osqueryd() {
    if command -v osqueryd &> /dev/null; then
        echo "osqueryd"
    elif [ -x "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd" ]; then
        # macOS: osqueryd is inside the app bundle
        echo "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd"
    else
        echo ""
    fi
}

# Check osquery availability early
if ! command -v osqueryi &> /dev/null && ! command -v docker &> /dev/null; then
    echo "ERROR: Neither osquery nor Docker is available"
    echo "Install osquery: brew install osquery (macOS) or see https://osquery.io/downloads"
    exit 1
fi

# Test examples FIRST (before starting background osquery)
# Example tests use osqueryi --extension which creates fresh osqueryi instances
test_examples

# If --examples-only, skip coverage
if [ "$EXAMPLES_ONLY" = true ]; then
    echo "Examples tested. Skipping coverage (--examples-only)."
    exit 0
fi

# Start fresh for coverage tests
cleanup
mkdir -p "$SOCKET_DIR"

# Find osqueryd for daemon mode (required for autoload tests)
OSQUERYD=$(find_osqueryd)

# Start background osqueryd for integration tests (daemon mode with autoload)
if [ -n "$OSQUERYD" ]; then
    echo "Using local osqueryd (daemon mode)..."

    SOCKET_PATH="$SOCKET_DIR/osquery.em"
    DB_PATH="$SOCKET_DIR/osquery.db"
    LOG_PATH="$SOCKET_DIR/logs"
    AUTOLOAD_PATH="$SOCKET_DIR/autoload"
    TEST_LOG_FILE="$SOCKET_DIR/test_logger.log"

    # Create directories
    mkdir -p "$LOG_PATH" "$AUTOLOAD_PATH"

    # Build the logger-file extension for autoload testing
    echo "Building logger-file extension for autoload..."
    cargo build -p logger-file --quiet

    # Get absolute path to the extension binary
    EXTENSION_BIN="$(pwd)/target/debug/logger-file"
    if [ ! -f "$EXTENSION_BIN" ]; then
        echo "ERROR: Extension binary not found at $EXTENSION_BIN"
        exit 1
    fi

    # osquery requires extensions to end in .ext for autoload
    EXTENSION_PATH="$AUTOLOAD_PATH/logger-file.ext"
    ln -sf "$EXTENSION_BIN" "$EXTENSION_PATH"

    # Create autoload configuration (just the path - osquery adds --socket automatically)
    echo "$EXTENSION_PATH" > "$AUTOLOAD_PATH/extensions.load"

    # Set the log file path via environment variable (the extension reads FILE_LOGGER_PATH)
    export FILE_LOGGER_PATH="$TEST_LOG_FILE"

    # Start osqueryd in ephemeral mode with autoload and file_logger plugin
    "$OSQUERYD" \
        --ephemeral \
        --disable_extensions=false \
        --extensions_socket="$SOCKET_PATH" \
        --extensions_autoload="$AUTOLOAD_PATH/extensions.load" \
        --extensions_timeout=30 \
        --database_path="$DB_PATH" \
        --logger_plugin=filesystem,file_logger \
        --logger_path="$LOG_PATH" \
        --config_path=/dev/null \
        --disable_watchdog \
        --force &
    OSQUERY_PID=$!

    # Export for integration tests
    export OSQUERY_SOCKET="$SOCKET_PATH"
    export TEST_LOGGER_FILE="$TEST_LOG_FILE"

# Fall back to osqueryi if osqueryd not available (limited functionality)
elif command -v osqueryi &> /dev/null; then
    echo "WARNING: osqueryd not found, using osqueryi (autoload test will fail)"
    echo "Install osquery daemon for full test coverage"

    # Start osqueryi with extensions enabled
    (
        while true; do sleep 60; done | osqueryi \
            --nodisable_extensions \
            --extensions_socket="$SOCKET_DIR/osquery.em" \
            2>/dev/null
    ) &
    OSQUERY_PID=$!
    export OSQUERY_SOCKET="$SOCKET_DIR/osquery.em"

# Fall back to Docker only on amd64 (osquery image is amd64-only)
elif command -v docker &> /dev/null; then
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
        echo "Using Docker (osquery not installed locally)..."
        USE_DOCKER=true

        docker run -d --name "$CONTAINER_NAME" \
            -v "$SOCKET_DIR:/var/osquery" \
            "$OSQUERY_IMAGE" \
            osqueryd --ephemeral --disable_extensions=false \
            --extensions_socket=/var/osquery/osquery.em

        export OSQUERY_SOCKET="$SOCKET_DIR/osquery.em"
    else
        echo "ERROR: osquery not installed and Docker image only supports amd64"
        echo "Install osquery: brew install osquery"
        exit 1
    fi
fi

# Wait for socket (30s timeout)
echo "Waiting for osquery socket..."
for i in {1..30}; do
    if [ -S "$OSQUERY_SOCKET" ]; then
        echo "Socket ready"
        break
    fi
    sleep 1
done

if [ ! -S "$OSQUERY_SOCKET" ]; then
    echo "ERROR: osquery socket not found after 30s"
    if [ "$USE_DOCKER" = true ]; then
        docker logs "$CONTAINER_NAME"
    fi
    exit 1
fi

# Give extension time to register with osquery
sleep 2

echo "Running coverage..."
if [ "$HTML_REPORT" = true ]; then
    cargo llvm-cov --all-features --workspace --html --ignore-filename-regex "_osquery"
    echo "HTML report: target/llvm-cov/html/index.html"
else
    cargo llvm-cov --all-features --workspace --ignore-filename-regex "_osquery"
fi
