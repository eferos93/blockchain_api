# OpenBao Keystore Integration

This document explains how to use OpenBao as a secure keystore for blockchain private keys.

## Quick Start

### 1. Start OpenBao Server

```bash
# Development mode (DO NOT use in production)
docker-compose -f docker-compose.openbao.yml up -d

# Verify OpenBao is running
curl http://localhost:8200/v1/sys/health
```

### 2. Initialize OpenBao in your application

```go
import "blockchain-api/keystore"

config := keystore.OpenBaoConfig{
    Address:    "http://localhost:8200",
    Token:      "myroot", // Dev token
    SecretPath: "secret/blockchain-keys",
}

configJSON, _ := json.Marshal(config)
err := keystore.InitializeKeystore("openbao", string(configJSON), "")
```

### 3. Store and retrieve keys

```go
// Store a blockchain private key
err = keystore.GlobalKeystore.StoreKey("user123", "Org1MSP", privateKeyPEM, certificatePEM)

// Retrieve the key
entry, err := keystore.GlobalKeystore.RetrieveKey("Org1MSP-user123")
```

## Production Setup

### 1. Secure Configuration

Create a production OpenBao configuration file:

```json
{
  "listener": {
    "tcp": {
      "address": "0.0.0.0:8200",
      "tls_cert_file": "/etc/openbao/tls/cert.pem",
      "tls_key_file": "/etc/openbao/tls/key.pem"
    }
  },
  "storage": {
    "file": {
      "path": "/openbao/data"
    }
  },
  "api_addr": "https://openbao.yourdomain.com:8200",
  "cluster_addr": "https://openbao.yourdomain.com:8201",
  "ui": true
}
```

### 2. Initialize and Unseal

```bash
# Initialize OpenBao (run once)
openbao operator init

# Unseal OpenBao (run after each restart)
openbao operator unseal <unseal-key-1>
openbao operator unseal <unseal-key-2>
openbao operator unseal <unseal-key-3>
```

### 3. Setup Authentication

```bash
# Enable AppRole authentication
openbao auth enable approle

# Create a policy for blockchain key access
openbao policy write blockchain-keys - <<EOF
path "secret/blockchain-keys/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/blockchain-keys/salts/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Create an AppRole
openbao write auth/approle/role/blockchain-api \
    token_policies="blockchain-keys" \
    token_ttl=1h \
    token_max_ttl=4h
```

### 4. Production Configuration

```go
config := keystore.OpenBaoConfig{
    Address:    "https://openbao.yourdomain.com:8200",
    Token:      os.Getenv("OPENBAO_TOKEN"), // Get from environment
    SecretPath: "secret/blockchain-keys",
}
```

## Environment Variables

Set these environment variables for production:

```bash
export OPENBAO_ADDR="https://openbao.yourdomain.com:8200"
export OPENBAO_TOKEN="your-production-token"
export OPENBAO_SECRET_PATH="secret/blockchain-keys"
```

## Security Best Practices

1. **Use TLS in production** - Always encrypt communication
2. **Token rotation** - Regularly rotate authentication tokens
3. **Least privilege** - Grant minimal required permissions
4. **Audit logging** - Enable and monitor audit logs
5. **Backup** - Regularly backup OpenBao data and keys
6. **Network security** - Restrict network access to OpenBao

## Migration from BadgerDB

To migrate from existing BadgerDB:

1. **Export existing keys** from BadgerDB
2. **Start OpenBao** with the configuration above
3. **Update your application** to use `keystoreType: "openbao"`
4. **Import keys** using the OpenBao keystore methods

## API Reference

### OpenBaoConfig

```go
type OpenBaoConfig struct {
    Address    string `json:"address"`    // OpenBao server URL
    Token      string `json:"token"`      // Authentication token
    SecretPath string `json:"secretPath"` // Base path for secrets
}
```

### Key Methods

- `StoreKey(enrollmentID, mspID, privateKeyPEM, certificatePEM)` - Store a private key
- `RetrieveKey(storageKey)` - Retrieve a private key
- `DeleteKey(enrollmentID, mspID, storageKey)` - Delete a key
- `StoreSalt(key, salt)` - Store a salt value
- `GetSalt(key)` - Retrieve a salt value
- `HealthCheck()` - Check OpenBao connectivity

## Troubleshooting

### Common Issues

1. **Connection refused** - Ensure OpenBao is running and accessible
2. **Authentication failed** - Verify token is valid and has required permissions
3. **Sealed vault** - OpenBao needs to be unsealed after startup
4. **Permission denied** - Check token policies and secret path permissions

### Debug Commands

```bash
# Check OpenBao status
curl http://localhost:8200/v1/sys/health

# Verify authentication
curl -H "X-Vault-Token: $OPENBAO_TOKEN" \
     http://localhost:8200/v1/auth/token/lookup-self

# List secret engines
curl -H "X-Vault-Token: $OPENBAO_TOKEN" \
     http://localhost:8200/v1/sys/mounts
```
