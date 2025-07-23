#!/bin/bash

# File-based keystore test setup script
# This script boots up a single blockchain API container using file-based keystore
# and loads all identities from the identities/ directory

set -e

# Configuration
KEYSTORE_DIR="./file_keystore_data"
CONTAINER_NAME="blockchain-api-filestore-test"

echo "=== File-based Keystore Test Setup ==="

# Clean up any existing container
echo "Cleaning up existing containers..."
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true

# Create keystore directory
echo "Creating keystore directory..."
mkdir -p "$KEYSTORE_DIR"

# Load identities into file keystore
echo "Loading identities into file keystore..."
go run scripts/load_identities_file_keystore.go "$KEYSTORE_DIR"

if [ $? -ne 0 ]; then
    echo "❌ Failed to load identities"
    exit 1
fi

echo "✓ Identities loaded successfully"

# Create configuration for file keystore
KEYSTORE_CONFIG_JSON='{
    "basePath": "/app/keystore_data",
    "salt": ""
}'

echo "✓ Created file keystore configuration"

# Start the container with file keystore
echo "Starting blockchain API container with file-based keystore..."
docker run -d \
    --name "$CONTAINER_NAME" \
    -p 3000:3000 \
    -v "$(pwd)/$KEYSTORE_DIR:/app/keystore_data" \
    -e KEYSTORE_TYPE=file \
    -e KEYSTORE_CONFIG="$KEYSTORE_CONFIG_JSON" \
    -e KEYSTORE_PASSWORD=master123 \
    blockchain_api

# Wait for container to start
echo "Waiting for container to start..."
sleep 5

# Check if container is running
if docker ps | grep -q "$CONTAINER_NAME"; then
    echo "✅ Container started successfully!"
    
    # Show container logs
    echo ""
    echo "=== Container Logs ==="
    docker logs "$CONTAINER_NAME"
    
    echo ""
    echo "=== Test Environment Ready ==="
    echo "Container name: $CONTAINER_NAME"
    echo "API endpoint: http://localhost:3000"
    echo "Keystore type: file-based"
    echo "Keystore data: $KEYSTORE_DIR"
    echo ""
    echo "Available test identities (password: test123):"
    echo "  - bsc-admin0"
    echo "  - bsc-peer0"
    echo "  - bsc-registrar0"
    echo "  - bsc-blockclient"
    echo "  - ub-admin0"
    echo "  - ub-registrar0"
    echo ""
    echo "To stop the test environment: docker stop $CONTAINER_NAME"
    echo "To view logs: docker logs -f $CONTAINER_NAME"
else
    echo "❌ Failed to start container"
    docker logs "$CONTAINER_NAME"
    exit 1
fi
