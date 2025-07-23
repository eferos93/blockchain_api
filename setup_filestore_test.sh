#!/bin/bash

# File-based keystore test setup script
# This script boots up a blockchain API using Docker Compose with file-based keystore
# and loads all identities from the identities/ directory

set -e

# Configuration
KEYSTORE_DIR="./file_keystore_data"
COMPOSE_FILE="docker-compose-filestore.yml"

echo "=== File-based Keystore Test Setup ==="

# Clean up any existing containers
echo "Cleaning up existing containers..."
docker-compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true

# Clean keystore directory
echo "Cleaning keystore directory..."
rm -rf "$KEYSTORE_DIR"
mkdir -p "$KEYSTORE_DIR"

# Load identities into file keystore
echo "Loading identities into file keystore..."
go run scripts/load_identities_file_keystore.go "$KEYSTORE_DIR"

if [ $? -ne 0 ]; then
    echo "❌ Failed to load identities"
    exit 1
fi

echo "✓ Identities loaded successfully into $KEYSTORE_DIR"

# Build and start the services
echo "Building and starting blockchain API with file-based keystore..."
docker-compose -f "$COMPOSE_FILE" up --build -d

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 10

# Check if the service is healthy
echo "Checking service health..."
for i in {1..30}; do
    if curl -f http://localhost:3000/health >/dev/null 2>&1; then
        echo "✅ Service is healthy!"
        break
    elif [ $i -eq 30 ]; then
        echo "❌ Service health check failed after 30 attempts"
        echo "Container logs:"
        docker-compose -f "$COMPOSE_FILE" logs
        exit 1
    else
        echo "Waiting for service... ($i/30)"
        sleep 2
    fi
done

echo ""
echo "=== Test Environment Ready ==="
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
echo "Management commands:"
echo "  View logs: docker-compose -f $COMPOSE_FILE logs -f"
echo "  Stop: docker-compose -f $COMPOSE_FILE down"
echo "  Restart: docker-compose -f $COMPOSE_FILE restart"
echo ""

# Test basic API endpoint
echo "Testing basic API connectivity..."
if curl -f http://localhost:3000/health >/dev/null 2>&1; then
    echo "✅ API is responding on http://localhost:3000"
else
    echo "⚠️  API health check endpoint not available, but service appears to be running"
fi

echo ""
echo "=== Setup Complete ==="
