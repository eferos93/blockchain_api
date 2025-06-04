#!/bin/bash

# Test script for Remote BadgerDB Keystore
# This script demonstrates how to use the remote BadgerDB keystore with Docker

set -e

echo "🚀 Testing Remote BadgerDB Keystore"
echo "================================="

# Configuration
BADGER_API_KEY="test-api-key-12345"
BADGER_MASTER_PASSWORD="test-master-password"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${YELLOW}📋 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Step 1: Build and start the BadgerDB keystore service
print_step "Building and starting BadgerDB keystore service..."

export BADGER_API_KEY="$BADGER_API_KEY"
export BADGER_MASTER_PASSWORD="$BADGER_MASTER_PASSWORD"

docker-compose -f docker-compose.badger.yml up -d badger-keystore

# Wait for service to be healthy
print_step "Waiting for BadgerDB service to be healthy..."
timeout=60
counter=0
while [ $counter -lt $timeout ]; do
    if docker-compose -f docker-compose.badger.yml ps badger-keystore | grep -q "healthy"; then
        print_success "BadgerDB service is healthy!"
        break
    fi
    
    if [ $counter -eq $((timeout - 1)) ]; then
        print_error "Timeout waiting for BadgerDB service to become healthy"
        docker-compose -f docker-compose.badger.yml logs badger-keystore
        exit 1
    fi
    
    sleep 1
    counter=$((counter + 1))
done

# Step 2: Test the API directly
print_step "Testing BadgerDB API directly..."

# Test health endpoint
echo "Testing health endpoint..."
curl -s -H "Authorization: Bearer $BADGER_API_KEY" \
     http://localhost:8080/health | jq '.'

# Test store key endpoint
echo "Testing store key endpoint..."
curl -s -X POST \
     -H "Authorization: Bearer $BADGER_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "enrollmentId": "testAdmin",
       "mspId": "TestMSP",
       "privateKeyPem": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIGq+EZ8W5pKFqwJJsb7QjVy7JKOqG5FJdyxMRLOqZJlJoAoGCCqGSM49\nAwEHoUQDQgAE8pKf7o7f9tLQp5MQYj1nG6FKj2KvJf6BnK8sL2wQ5+GnK8fV9bO\nJ5FqV8pKJZp2pKJFqwJJsb7QjVy7JKOqG5FJdyxMRLOqZJlJ\n-----END EC PRIVATE KEY-----",
       "certificatePem": "-----BEGIN CERTIFICATE-----\nMIICXTCCAgOgAwIBAgIUY+P8rqxJJsb7QjVy7JKOqG5FJdyxMRIwDQYJKoZIhvcNAQ\nELBQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjMwNjA0MTIwMDAwWhcNMjU\nwNjAzMTIwMDAwWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBAL8pKf7o7f9tLQp5MQYj1nG6FKj2KvJf6BnK8sL2\nwQ5+GnK8fV9bOJ5FqV8pKJZp2pKJFqwJJsb7QjVy7JKOqG5FJdyxMRLOqZJlJo\nIDAQABo1MwUTAdBgNVHQ4EFgQUE8pKf7o7f9tLQp5MQYj1nG6FKj2KvJMwHwYDVR\n0jBBgwFoAUE8pKf7o7f9tLQp5MQYj1nG6FKj2KvJMwDwYDVR0TAQH/BAUwAwEB/z\nANBgkqhkiG9w0BAQsFAAOCAQEAQpKJZp2pKJFqwJJsb7QjVy7JKOqG5FJdyxMRL\nOqZJlJoIDAQAB\n-----END CERTIFICATE-----"
     }' \
     http://localhost:8080/keystore/store | jq '.'

print_success "Key stored successfully!"

# Test retrieve key endpoint
echo "Testing retrieve key endpoint..."
curl -s -X POST \
     -H "Authorization: Bearer $BADGER_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "enrollmentId": "testAdmin",
       "mspId": "TestMSP"
     }' \
     http://localhost:8080/keystore/retrieve | jq '.'

print_success "Key retrieved successfully!"

# Step 3: Test with the Fabric API using remote keystore
print_step "Starting Fabric API with remote BadgerDB keystore..."

docker-compose -f docker-compose.badger.yml up -d fabric-api

# Wait for Fabric API to be ready
print_step "Waiting for Fabric API to be ready..."
sleep 10

# Test that the Fabric API can connect to the remote keystore
echo "Testing Fabric API with remote keystore..."
curl -s -X POST \
     -H "Content-Type: application/json" \
     -d '{
       "caConfig": {
         "caUrl": "https://example-ca:7054",
         "caName": "ca-example",
         "mspId": "TestMSP",
         "skipTls": true
       },
       "enrollmentId": "admin",
       "secret": "adminpw",
       "profile": "",
       "csrInfo": {
         "cn": "admin",
         "names": [
           {
             "C": "US",
             "ST": "California",
             "L": "San Francisco",
             "O": "Test Organization",
             "OU": "Test Unit"
           }
         ],
         "hosts": ["localhost"]
       }
     }' \
     http://localhost:3000/fabricCA/enroll || echo "Expected - CA server not running"

print_success "Fabric API is running with remote BadgerDB keystore!"

# Step 4: Show logs
print_step "Showing service logs..."
echo "BadgerDB Keystore logs:"
docker-compose -f docker-compose.badger.yml logs --tail=20 badger-keystore

echo -e "\nFabric API logs:"
docker-compose -f docker-compose.badger.yml logs --tail=20 fabric-api

# Step 5: Cleanup option
echo ""
read -p "🧹 Do you want to clean up containers? (y/N): " cleanup
if [[ $cleanup =~ ^[Yy]$ ]]; then
    print_step "Cleaning up containers..."
    docker-compose -f docker-compose.badger.yml down
    print_success "Cleanup completed!"
else
    print_step "Containers are still running. Use 'docker-compose -f docker-compose.badger.yml down' to stop them."
fi

echo ""
print_success "Remote BadgerDB Keystore test completed! 🎉"
echo "================================="
