#!/usr/bin/env bash
set -euo pipefail

# Coverage script with osquery for integration tests
# Usage: ./scripts/coverage.sh [--html]
#
# This script mirrors the CI coverage workflow, enabling local verification
# before pushing changes.
#
# Platform handling:
# - Uses local osqueryi if available (preferred, works on all platforms)
# - Falls back to Docker on amd64 only (osquery image is amd64-only)

OSQUERY_IMAGE="osquery/osquery:5.17.0-ubuntu22.04"
SOCKET_DIR="/tmp/osquery-coverage"
CONTAINER_NAME="osquery-coverage"
OSQUERY_PID=""
USE_DOCKER=false

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
    rm -rf "$SOCKET_DIR" 2>/dev/null
    set -e
}

trap cleanup EXIT

# Start fresh
cleanup
mkdir -p "$SOCKET_DIR"

# Prefer local osquery (works on all platforms including ARM)
if command -v osqueryi &> /dev/null; then
    echo "Using local osquery..."

    # Start osqueryi with extensions enabled, keeping stdin open
    (
        while true; do sleep 60; done | osqueryi \
            --nodisable_extensions \
            --extensions_socket="$SOCKET_DIR/osquery.em" \
            2>/dev/null
    ) &
    OSQUERY_PID=$!

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
    else
        echo "ERROR: osquery not installed and Docker image only supports amd64"
        echo "Install osquery: brew install osquery"
        exit 1
    fi
else
    echo "ERROR: Neither osquery nor Docker is available"
    echo "Install osquery: brew install osquery (macOS) or see https://osquery.io/downloads"
    exit 1
fi

# Wait for socket (30s timeout)
echo "Waiting for osquery socket..."
for i in {1..30}; do
    if [ -S "$SOCKET_DIR/osquery.em" ]; then
        echo "Socket ready"
        break
    fi
    sleep 1
done

if [ ! -S "$SOCKET_DIR/osquery.em" ]; then
    echo "ERROR: osquery socket not found after 30s"
    if [ "$USE_DOCKER" = true ]; then
        docker logs "$CONTAINER_NAME"
    fi
    exit 1
fi

export OSQUERY_SOCKET="$SOCKET_DIR/osquery.em"

echo "Running coverage..."
if [[ "${1:-}" == "--html" ]]; then
    cargo llvm-cov --all-features --workspace --html --ignore-filename-regex "_osquery"
    echo "HTML report: target/llvm-cov/html/index.html"
else
    cargo llvm-cov --all-features --workspace --ignore-filename-regex "_osquery"
fi
