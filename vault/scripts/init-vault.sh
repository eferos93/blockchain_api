#!/bin/bash
# Vault initialization script for blockchain-api keystore
# Run this after Vault is started and unsealed

set -e

VAULT_ADDR="${VAULT_ADDR:-http://localhost:6000}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"

export VAULT_ADDR
export VAULT_TOKEN

echo "Configuring Vault at $VAULT_ADDR..."

# Wait for Vault to be ready
until vault status > /dev/null 2>&1; do
    echo "Waiting for Vault..."
    sleep 2
done

echo "Vault is ready. Starting configuration..."

# Enable Transit secrets engine
echo "Enabling Transit secrets engine..."
vault secrets enable -path=transit transit 2>/dev/null || echo "Transit already enabled"

# Create Transit key for encryption-as-a-service
echo "Creating Transit key for blockchain-api..."
vault write -f transit/keys/blockchain-api-key \
    type=aes256-gcm96 \
    derived=true \
    convergent_encryption=true \
    exportable=false 2>/dev/null || echo "Transit key already exists"

# Enable KV v2 secrets engine (if not already enabled)
echo "Enabling KV v2 secrets engine..."
vault secrets enable -path=secret -version=2 kv 2>/dev/null || echo "KV already enabled"

# Create policy for blockchain-api service
echo "Creating blockchain-api policy..."
vault policy write blockchain-api - <<EOF
# KV v2 secrets access for blockchain-api
path "secret/data/blockchain-api/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/blockchain-api/*" {
  capabilities = ["list", "delete"]
}

path "secret/delete/blockchain-api/*" {
  capabilities = ["update"]
}

path "secret/undelete/blockchain-api/*" {
  capabilities = ["update"]
}

path "secret/destroy/blockchain-api/*" {
  capabilities = ["update"]
}

# Transit encryption/decryption
path "transit/encrypt/blockchain-api-key" {
  capabilities = ["update"]
}

path "transit/decrypt/blockchain-api-key" {
  capabilities = ["update"]
}

path "transit/rewrap/blockchain-api-key" {
  capabilities = ["update"]
}

# Allow reading key metadata (not the key itself)
path "transit/keys/blockchain-api-key" {
  capabilities = ["read"]
}

# Allow key rotation
path "transit/keys/blockchain-api-key/rotate" {
  capabilities = ["update"]
}

# Health check
path "sys/health" {
  capabilities = ["read"]
}
EOF

# Enable AppRole authentication
echo "Enabling AppRole authentication..."
vault auth enable approle 2>/dev/null || echo "AppRole already enabled"

# Create AppRole for blockchain-api
echo "Creating AppRole for blockchain-api..."
vault write auth/approle/role/blockchain-api \
    token_policies="blockchain-api" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=720h \
    secret_id_num_uses=0

# Get AppRole credentials
ROLE_ID=$(vault read -field=role_id auth/approle/role/blockchain-api/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/blockchain-api/secret-id)

echo ""
echo "=========================================="
echo "Vault Configuration Complete!"
echo "=========================================="
echo ""
echo "Development Token: $VAULT_TOKEN"
echo ""
echo "AppRole Credentials (for production):"
echo "  Role ID:   $ROLE_ID"
echo "  Secret ID: $SECRET_ID"
echo ""
echo "To authenticate with AppRole:"
echo "  vault write auth/approle/login role_id=$ROLE_ID secret_id=$SECRET_ID"
echo ""
echo "Environment variables for blockchain-api:"
echo "  KEYSTORE_TYPE=vault"
echo "  KEYSTORE_CONFIG='{\"address\":\"$VAULT_ADDR\",\"token\":\"$VAULT_TOKEN\",\"mountPath\":\"secret\",\"transitPath\":\"transit\",\"transitKey\":\"blockchain-api-key\"}'"
echo ""
echo "=========================================="
