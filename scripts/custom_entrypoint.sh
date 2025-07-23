#!/bin/bash
# Custom entrypoint for OpenBao test container

set -e

echo "🔧 Starting OpenBao test container..."

# Start OpenBao in development mode in the background
echo "🚀 Starting OpenBao server..."
openbao server -dev -dev-root-token-id=myroot -dev-listen-address=0.0.0.0:8200 &

# Wait for OpenBao to be ready
echo "⏳ Waiting for OpenBao to be ready..."
until openbao status > /dev/null 2>&1; do
    sleep 1
done

echo "✅ OpenBao is ready!"

# Run our test identity loading script
echo "📝 Loading test identities..."
if [ -f "/scripts/load_test_identities.sh" ]; then
    /scripts/load_test_identities.sh
else
    echo "⚠️ Test identity loading script not found, skipping..."
fi

echo "🎉 OpenBao test container setup complete!"

# Keep the container running
wait
