#!/bin/bash
# Archon Social Registry Publisher
# Extracts names from the server and publishes to IPNS

set -e

# Configuration
ARCHON_API="http://localhost:3000"
IPNS_KEY="archon-social"  # Change if using different key name
OUTPUT_FILE="/tmp/archon-registry.json"

echo "[$(date)] Starting registry publish..."

# Get registry from the API (already formatted correctly)
echo "Fetching registry from API..."
curl -s "${ARCHON_API}/api/registry" > "$OUTPUT_FILE"

if [ ! -s "$OUTPUT_FILE" ]; then
    echo "ERROR: Could not fetch registry from API. Is archon-social running?"
    exit 1
fi

echo "Registry content:"
cat "$OUTPUT_FILE"
echo ""

# Add to IPFS
echo "Adding to IPFS..."
CID=$(ipfs add -Q "$OUTPUT_FILE")
echo "CID: $CID"

# Publish to IPNS
echo "Publishing to IPNS with key: $IPNS_KEY..."
RESULT=$(ipfs name publish --key="$IPNS_KEY" "/ipfs/$CID" 2>&1)
echo "$RESULT"

echo ""
echo "[$(date)] Registry published successfully!"
echo "View at: https://ipfs.io/ipns/archon.social"
