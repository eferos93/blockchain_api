# Vault Keystore for Blockchain API

This document describes how to use HashiCorp Vault as the keystore backend for the Blockchain API.

## Overview

The Vault keystore implementation provides enterprise-grade secrets management with:

- **Transit Secrets Engine**: Encryption-as-a-service (keys never leave Vault)
- **KV v2 Secrets Engine**: Versioned secret storage with metadata
- **Password-based context**: User passwords create unique encryption contexts
- **Key rotation**: Rotate encryption keys without re-encrypting all data
- **Audit logging**: Track all secret access (when configured)

## Architecture

```
┌─────────────────────┐     ┌─────────────────────┐
│   Blockchain API    │     │       Vault         │
│                     │     │                     │
│  ┌───────────────┐  │     │  ┌───────────────┐  │
│  │ VaultKeystore │──┼────▶│  │    Transit    │  │
│  │               │  │     │  │   (encrypt/   │  │
│  │ StoreKey()    │  │     │  │   decrypt)    │  │
│  │ RetrieveKey() │  │     │  └───────────────┘  │
│  │ DeleteKey()   │  │     │                     │
│  └───────────────┘  │     │  ┌───────────────┐  │
│                     │     │  │    KV v2      │  │
│                     │─────┼─▶│  (encrypted   │  │
│                     │     │  │   storage)    │  │
└─────────────────────┘     │  └───────────────┘  │
                            └─────────────────────┘
```

## Quick Start (Development)

### 1. Start Vault in Dev Mode

```bash
# Using Docker Compose with the test-vault profile
docker-compose --profile test-vault up -d vault

# Or standalone
docker run -d --name vault \
  --cap-add=IPC_LOCK \
  -p 6000:6000 \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-root-token \
  hashicorp/vault:1.15 server -dev
```

### 2. Initialize Vault for Blockchain API

```bash
# Set environment variables
export VAULT_ADDR=http://localhost:6000
export VAULT_TOKEN=dev-root-token

# Run initialization script
./vault/scripts/init-vault.sh
```

### 3. Configure Blockchain API

Set the following environment variables:

```bash
export KEYSTORE_TYPE=vault
export KEYSTORE_CONFIG='{"address":"http://vault:6000","token":"dev-root-token","mountPath":"secret","transitPath":"transit","transitKey":"blockchain-api-key"}'
```

Or in your `.env` file:

```env
KEYSTORE_TYPE=vault
KEYSTORE_CONFIG={"address":"http://vault:6000","token":"dev-root-token","mountPath":"secret","transitPath":"transit","transitKey":"blockchain-api-key"}
```

### 4. Start Blockchain API with Vault

```bash
docker-compose --profile test-vault up -d
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `address` | Vault server URL | (required) |
| `token` | Authentication token | (required) |
| `mountPath` | KV v2 mount path | `secret` |
| `transitPath` | Transit engine mount path | `transit` |
| `transitKey` | Transit key name | `blockchain-api-key` |
| `namespace` | Vault namespace (Enterprise) | (none) |
| `tlsConfig.caCert` | CA certificate path | (none) |
| `tlsConfig.clientCert` | Client certificate path | (none) |
| `tlsConfig.clientKey` | Client key path | (none) |
| `tlsConfig.insecure` | Skip TLS verification | `false` |

### Full Configuration Example

```json
{
  "address": "https://vault.example.com:6000",
  "token": "s.xxxxxxxxxxxxx",
  "mountPath": "secret",
  "transitPath": "transit",
  "transitKey": "blockchain-api-key",
  "namespace": "blockchain",
  "tlsConfig": {
    "caCert": "/path/to/ca.crt",
    "clientCert": "/path/to/client.crt",
    "clientKey": "/path/to/client.key",
    "insecure": false
  }
}
```

## Production Deployment

### 1. Use AppRole Authentication

Instead of using a static token, use AppRole for automatic token renewal:

```bash
# Get AppRole credentials from Vault admin
ROLE_ID=<role-id>
SECRET_ID=<secret-id>

# Login to get a token
vault write auth/approle/login \
  role_id=$ROLE_ID \
  secret_id=$SECRET_ID
```

### 2. Enable TLS

```json
{
  "address": "https://vault.example.com:6000",
  "token": "s.xxxxxxxxxxxxx",
  "tlsConfig": {
    "caCert": "/etc/vault/ca.crt"
  }
}
```

### 3. Configure Vault HA

For high availability, deploy Vault in HA mode with Consul or Raft storage backend.

### 4. Enable Audit Logging

```bash
vault audit enable file file_path=/vault/logs/audit.log
```

## Key Rotation

The Vault keystore supports automatic key rotation:

### Rotate the Transit Key

```bash
vault write -f transit/keys/blockchain-api-key/rotate
```

### Rewrap Existing Entries

After rotation, existing entries can be rewrapped with the new key version:

```go
vaultKeystore.RotateTransitKey()
vaultKeystore.RewrapEntry(username, password)
```

Or via the API (if exposed).

## Security Considerations

1. **Token Security**: Never commit tokens to version control
2. **Network Security**: Always use TLS in production
3. **Access Control**: Use minimal permissions with Vault policies
4. **Audit**: Enable audit logging for compliance
5. **Key Rotation**: Rotate Transit keys periodically
6. **Namespace Isolation**: Use Vault namespaces for multi-tenancy

## Troubleshooting

### Vault is sealed

```bash
vault operator unseal <unseal-key>
```

### Token expired

```bash
vault token renew
# Or re-authenticate with AppRole
```

### Transit key not found

```bash
# Check if Transit is enabled
vault secrets list

# Create the key
vault write -f transit/keys/blockchain-api-key \
  type=aes256-gcm96 \
  derived=true \
  convergent_encryption=true
```

### Connection refused

- Check Vault is running: `vault status`
- Check network connectivity
- Verify `VAULT_ADDR` is correct

## API Reference

### VaultKeystore Methods

| Method | Description |
|--------|-------------|
| `NewVaultKeystore(config)` | Create new Vault keystore |
| `StoreKey(username, password, privateKey, cert, tlsCert)` | Store encrypted key material |
| `RetrieveKey(username, password)` | Retrieve and decrypt key material |
| `DeleteKey(username, password)` | Delete key material |
| `HealthCheck()` | Verify Vault connectivity |
| `ListUsers()` | List all users (admin) |
| `RotateTransitKey()` | Rotate the Transit encryption key |
| `RewrapEntry(username, password)` | Re-encrypt with latest key version |

## Comparison with File Keystore

| Feature | File Keystore | Vault Keystore |
|---------|---------------|----------------|
| Storage | Local filesystem | Centralized Vault |
| Encryption | AES-256-GCM (local) | Transit engine (HSM-capable) |
| Key Rotation | Manual re-encryption | Automatic with rewrap |
| Audit | None | Full audit logging |
| HA | Requires shared storage | Built-in HA support |
| Access Control | File permissions | Vault policies |
| Scalability | Single node | Multi-node cluster |
