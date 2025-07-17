#!/bin/bash

# OpenBao startup script for test container
# This script starts OpenBao and then loads test identities

set -e

echo "🚀 Starting OpenBao test container..."

# Start OpenBao in the background
echo "📦 Starting OpenBao server..."
openbao server -dev &
OPENBAO_PID=$!

# Function to cleanup on exit
cleanup() {
    echo "🛑 Shutting down OpenBao..."
    kill $OPENBAO_PID 2>/dev/null || true
    wait $OPENBAO_PID 2>/dev/null || true
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Wait a bit for OpenBao to start
echo "⏳ Waiting for OpenBao to initialize..."
sleep 5

# Load test identities
echo "🔑 Loading test identities..."
if [ -f "/scripts/load_test_identities.sh" ]; then
    /scripts/load_test_identities.sh
else
    echo "⚠️  Identity loading script not found, skipping..."
fi

echo "✅ OpenBao test container ready!"

# Wait for OpenBao process
wait $OPENBAO_PID
