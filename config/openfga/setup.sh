#!/bin/sh
# OpenFGA bootstrap for ToolMesh.
# Run via: docker compose run --rm fga-setup
#
# Creates a store, writes the authorization model, and loads tuples.
# The resulting OPENFGA_STORE_ID must be copied into .env.
set -e

FGA_API_URL="${FGA_API_URL:-http://openfga:8080}"
CONFIG_DIR="$(dirname "$0")"

echo "==> Creating OpenFGA store..."
STORE_ID=$(fga store create --api-url "$FGA_API_URL" --name toolmesh 2>/dev/null | grep store_id | awk '{print $NF}')

if [ -z "$STORE_ID" ]; then
  echo "ERROR: Failed to create store" >&2
  exit 1
fi
echo "    Store ID: $STORE_ID"

echo "==> Writing authorization model..."
MODEL_ID=$(fga model write --api-url "$FGA_API_URL" --store-id "$STORE_ID" --file "$CONFIG_DIR/model.fga" 2>/dev/null | grep model_id | awk '{print $NF}')
echo "    Model ID: $MODEL_ID"

echo "==> Writing tuples..."
fga tuple write --api-url "$FGA_API_URL" --store-id "$STORE_ID" --file "$CONFIG_DIR/tuples.json"

echo ""
echo "Bootstrap complete!"
echo ""
echo "Add this to your .env:"
echo "  OPENFGA_STORE_ID=$STORE_ID"
