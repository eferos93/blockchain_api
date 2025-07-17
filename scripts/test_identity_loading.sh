#!/bin/bash

# Script to test that identities are loaded in OpenBao
# Run this after the openbao-test container is up

OPENBAO_ADDR="http://localhost:8203"
OPENBAO_TOKEN="myroot"
SECRET_BASE_PATH="blockchain-keys"

echo "🔍 Testing OpenBao identity loading..."
echo "OpenBao Address: $OPENBAO_ADDR"

# Check if OpenBao is accessible
echo "📡 Checking OpenBao connectivity..."
if ! curl -s -f "${OPENBAO_ADDR}/v1/sys/health" > /dev/null; then
    echo "❌ Cannot connect to OpenBao at $OPENBAO_ADDR"
    exit 1
fi
echo "✅ OpenBao is accessible"

# List all stored identities
echo "📋 Listing stored identities..."
identities=$(curl -s -X GET \
    -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
    "${OPENBAO_ADDR}/v1/kv/metadata/${SECRET_BASE_PATH}?list=true" | \
    jq -r '.data.keys[]?' 2>/dev/null || echo "")

if [ -z "$identities" ]; then
    echo "❌ No identities found in keystore"
    exit 1
fi

echo "✅ Found identities:"
echo "$identities" | while read -r identity; do
    if [ -n "$identity" ]; then
        echo "  - $identity"
    fi
done

# Test retrieving a specific identity
test_identity=$(echo "$identities" | head -n 1)
if [ -n "$test_identity" ]; then
    echo "🔐 Testing retrieval of identity: $test_identity"
    
    # Try to retrieve the identity data
    response=$(curl -s -X GET \
        -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
        "${OPENBAO_ADDR}/v1/kv/data/${SECRET_BASE_PATH}/${test_identity}")
    
    if echo "$response" | jq -e '.data.data.enrollmentId' > /dev/null 2>&1; then
        echo "✅ Successfully retrieved identity data for: $test_identity"
        echo "📄 Identity details:"
        echo "$response" | jq '.data.data | {enrollmentId, createdAt}' 2>/dev/null || echo "  Could not parse identity details"
    else
        echo "❌ Failed to retrieve identity data for: $test_identity"
        echo "Response: $response"
        exit 1
    fi
fi

echo "🎉 All tests passed! Identities are successfully loaded in OpenBao."
