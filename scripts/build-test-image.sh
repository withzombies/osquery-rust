#!/bin/bash
# build-test-image.sh - Build the osquery-rust-test Docker image
#
# This script builds the multi-stage Docker image that contains
# osquery and the Rust extensions for integration testing.
#
# Usage:
#   ./scripts/build-test-image.sh [IMAGE_TAG]
#
# Arguments:
#   IMAGE_TAG - Optional tag for the image (default: osquery-rust-test:latest)

set -e

IMAGE_TAG="${1:-osquery-rust-test:latest}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Building osquery-rust-test Docker image ==="
echo "Image tag: $IMAGE_TAG"
echo "Project root: $PROJECT_ROOT"
echo ""

# Check that Dockerfile exists
if [ ! -f "$PROJECT_ROOT/docker/Dockerfile.test" ]; then
    echo "ERROR: docker/Dockerfile.test not found"
    echo "Expected path: $PROJECT_ROOT/docker/Dockerfile.test"
    exit 1
fi

# Build the image
echo "Building image (this may take a few minutes on first run)..."
docker build \
    -t "$IMAGE_TAG" \
    -f "$PROJECT_ROOT/docker/Dockerfile.test" \
    "$PROJECT_ROOT"

echo ""
echo "=== Build complete ==="
echo "Image: $IMAGE_TAG"
echo ""

# Verify the image - basic osquery works
echo "Verifying osquery..."
docker run --rm "$IMAGE_TAG" osqueryi --json "SELECT 1 AS test;"

# Verify Rust toolchain is present
echo ""
echo "Verifying Rust toolchain..."
docker run --rm "$IMAGE_TAG" cargo --version
docker run --rm "$IMAGE_TAG" rustc --version

# Verify ALL extensions load (start osqueryd, wait, query osquery_extensions)
echo ""
echo "Verifying all extensions load..."
docker run --rm "$IMAGE_TAG" sh -c '
/opt/osquery/bin/osqueryd --ephemeral --disable_extensions=false \
  --extensions_socket=/var/osquery/osquery.em \
  --extensions_autoload=/etc/osquery/extensions.load \
  --database_path=/tmp/osquery.db \
  --disable_watchdog --force 2>/dev/null &
for i in $(seq 1 15); do
  if [ -S /var/osquery/osquery.em ]; then sleep 3; break; fi
  sleep 1
done
echo "Loaded extensions:"
/usr/bin/osqueryi --connect /var/osquery/osquery.em --json "SELECT name, type FROM osquery_extensions WHERE name != \"core\";"
echo ""
echo "Testing two-tables extension (t1 table):"
/usr/bin/osqueryi --connect /var/osquery/osquery.em --json "SELECT * FROM t1 LIMIT 1;"
'

echo ""
echo "=== Image verified successfully ==="
echo ""
echo "To test extensions manually:"
echo "  docker run --rm $IMAGE_TAG sh -c '"
echo "    osqueryd --ephemeral --disable_extensions=false --extensions_socket=/var/osquery/osquery.em \\"
echo "      --extensions_autoload=/etc/osquery/extensions.load --database_path=/tmp/osquery.db \\"
echo "      --disable_watchdog --force &"
echo "    sleep 5"
echo "    osqueryi --connect /var/osquery/osquery.em \"SELECT * FROM t1;\"'"
echo ""
echo "To run cargo test inside container:"
echo "  docker run --rm -v \$(pwd):/workspace -w /workspace $IMAGE_TAG \\"
echo "    sh -c 'osqueryd --ephemeral ... & sleep 5 && cargo test --test integration_test'"
