#!/bin/bash
# Example script showing how to use different keystore types with the CA endpoints

set -e

echo "=== Secure Private Key Storage Demo ==="

# Generate environment variables if .env doesn't exist
if [ ! -f .env ]; then
    echo "Generating session keys and keystore password..."
    bash generate_session_keys.sh
    
    # Add keystore configuration to .env
    echo "" >> .env
    echo "# Keystore Configuration" >> .env
    echo "KEYSTORE_PASSWORD=$(head -c 32 /dev/urandom | xxd -p -c 32)" >> .env
    echo "KEYSTORE_TYPE=file" >> .env
    echo "KEYSTORE_CONFIG=./secure-keystore" >> .env
fi

# Load environment variables
source .env

echo "Environment configured:"
echo "- Keystore Type: ${KEYSTORE_TYPE:-file}"
echo "- Keystore Config: ${KEYSTORE_CONFIG:-./secure-keystore}"
echo "- Keystore Password: [HIDDEN]"

# Function to test different keystore types
test_keystore_type() {
    local type=$1
    local config=$2
    
    echo ""
    echo "=== Testing Keystore Type: $type ==="
    
    # Set environment variables for this test
    export KEYSTORE_TYPE=$type
    export KEYSTORE_CONFIG=$config
    
    # Start the API in background
    echo "Starting API server with $type keystore..."
    go run . &
    API_PID=$!
    
    # Wait for API to start
    sleep 3
    
    echo "Testing CA enrollment (stores in $type keystore)..."
    curl -s -X POST http://localhost:3000/fabricCA/enroll \
      -H "Content-Type: application/json" \
      -d '{
        "caConfig": {
          "caUrl": "https://localhost:10055",
          "caName": "ca-bsc",
          "mspId": "bscMSP",
          "skipTls": true
        },
        "enrollmentId": "testuser_'$type'",
        "secret": "testpass",
        "csrInfo": {
          "cn": "testuser_'$type'",
          "names": [{
            "C": "US",
            "ST": "California", 
            "L": "San Francisco",
            "O": "bsc",
            "OU": "client"
          }]
        }
      }' | jq . || echo "CA enrollment failed (CA server may not be running)"
    
    echo "Testing client initialization with keystore..."
    curl -s -X POST http://localhost:3000/client/ \
      -H "Content-Type: application/json" \
      -d '{
        "orgName": "bsc",
        "mspId": "bscMSP",
        "useKeystore": true,
        "enrollmentId": "testuser_'$type'",
        "tlsCertPath": "./identities/blockClient/msp/tlscacerts/cert.pem",
        "peerEndpoint": "dns:///localhost:9051",
        "gatewayPeer": "peer0.bsc.dt4h.com"
      }' || echo "Client initialization failed (expected if CA enrollment failed)"
    
    # Stop API
    kill $API_PID 2>/dev/null || true
    wait $API_PID 2>/dev/null || true
    
    # Show keystore contents
    echo "Keystore contents for $type:"
    case $type in
        "file")
            ls -la $config/ 2>/dev/null || echo "No keystore directory found"
            ;;
        "badger")
            ls -la $config* 2>/dev/null || echo "No database files found"
            ;;
    esac
}

# Test different keystore types
test_keystore_type "file" "./keystore-files"
test_keystore_type "badger" "./keystore-badger"

echo ""
echo "=== Demo Summary ==="
echo "Tested keystore types:"
echo "1. File (simple encrypted files)"
echo "2. Badger (high-performance key-value store)"
echo ""
echo "Performance comparison:"
echo "- File: Simple, good for small deployments, human-readable structure"
echo "- Badger: Fastest database option, LSM-tree based, production-ready"
echo ""
echo "Recommendations:"
echo "- Development/Small deployments: file"
echo "- Production/High-load: badger"
curl -s -X POST http://localhost:3000/fabricCA/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "caConfig": {
      "caUrl": "https://localhost:10055",
      "caName": "ca-bsc",
      "mspId": "bscMSP",
      "skipTls": true
    },
    "enrollmentId": "admin",
    "secret": "adminpw",
    "csrInfo": {
      "cn": "admin",
      "names": [{
        "C": "US",
        "ST": "California",
        "L": "San Francisco",
        "O": "bsc",
        "OU": "admin"
      }]
    }
  }' | jq .

echo -e "\n=== Testing Client with Keystore ==="
curl -s -X POST http://localhost:3000/client/ \
  -H "Content-Type: application/json" \
  -d '{
    "orgName": "bsc",
    "mspId": "bscMSP",
    "useKeystore": true,
    "enrollmentId": "admin",
    "tlsCertPath": "./identities/blockClient/msp/tlscacerts/cert.pem",
    "peerEndpoint": "dns:///localhost:9051",
    "gatewayPeer": "peer0.bsc.dt4h.com"
  }'

echo -e "\n=== Cleanup ==="
kill $API_PID 2>/dev/null || true

echo "Demo completed. Check the keystore directory for encrypted key storage:"
ls -la ${KEYSTORE_CONFIG:-./secure-keystore}/ 2>/dev/null || echo "Keystore directory not found (expected if CA server is not running)"
