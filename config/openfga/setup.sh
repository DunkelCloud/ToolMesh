#!/bin/sh
# OpenFGA bootstrap for ToolMesh.
# Run from the project root: ./config/openfga/setup.sh
#
# Creates a store, writes the authorization model, and loads tuples.
# The resulting OPENFGA_STORE_ID must be copied into .env.
#
# Prerequisites: docker compose up -d (with OpenFGA services uncommented)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NETWORK="${COMPOSE_PROJECT_NAME:-toolmesh}_default"
FGA_URL="http://openfga:8080"

fga() {
  docker run --rm --network "$NETWORK" \
    -v "$SCRIPT_DIR":/config:ro \
    openfga/cli:latest "$@"
}

echo "==> Creating OpenFGA store..."
STORE_OUTPUT=$(fga store create --api-url "$FGA_URL" --name toolmesh)
STORE_ID=$(echo "$STORE_OUTPUT" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$STORE_ID" ]; then
  echo "ERROR: Failed to create store. Output:" >&2
  echo "$STORE_OUTPUT" >&2
  exit 1
fi
echo "    Store ID: $STORE_ID"

echo "==> Writing authorization model..."
fga model write --api-url "$FGA_URL" --store-id "$STORE_ID" --file /config/model.fga

echo "==> Writing tuples..."
fga tuple write --api-url "$FGA_URL" --store-id "$STORE_ID" --file /config/tuples.json

echo ""
echo "Bootstrap complete!"
echo ""
echo "Add this to your .env:"
echo "  OPENFGA_STORE_ID=$STORE_ID"
