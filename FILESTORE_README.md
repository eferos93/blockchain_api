# File-based Keystore Test Mode

This directory contains setup scripts and configuration for testing the blockchain API with a file-based encrypted keystore instead of OpenBao.

## Overview

The file-based keystore provides an alternative to OpenBao that stores encrypted keys directly on the filesystem. Each user's keys are encrypted using AES-256-GCM with a password-derived key using PBKDF2.

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Setup and start the test environment
./setup_filestore_test.sh

# View logs
docker-compose -f docker-compose-filestore.yml logs -f

# Stop the environment
docker-compose -f docker-compose-filestore.yml down
```

### Using Docker Run

```bash
# Alternative setup using docker run
./run_filestore_test.sh
```

## Test Identities

The following test identities are automatically loaded with password `test123`:

### BSC Organization
- `bsc-admin0` - Administrator identity
- `bsc-peer0` - Peer node identity  
- `bsc-registrar0` - Registration authority
- `bsc-blockclient` - Block client identity

### UB Organization  
- `ub-admin0` - Administrator identity
- `ub-registrar0` - Registration authority

## API Usage

Once running, the API is available at `http://localhost:3000`

### Example API calls

```bash
# Test client endpoint with bsc-admin0 identity
curl -X POST http://localhost:3000/client \
  -H "Content-Type: application/json" \
  -d '{
    "username": "bsc-admin0",
    "password": "test123",
    "org": "bsc"
  }'

# Test query endpoint
curl "http://localhost:3000/client/query?key=somekey"
```

## Configuration

The file-based keystore is configured via environment variables:

- `KEYSTORE_TYPE=file` - Selects file-based keystore
- `KEYSTORE_CONFIG` - JSON configuration for keystore
- `KEYSTORE_PASSWORD` - Master password for keystore operations

### Default Configuration

```json
{
  "basePath": "/app/keystore_data",
  "salt": ""
}
```

## File Structure

```
file_keystore_data/
├── bsc-admin0/
│   └── keystore.json          # Encrypted keystore entry
├── bsc-peer0/
│   └── keystore.json
└── ...
```

Each `keystore.json` contains:
- Encrypted private key (AES-256-GCM)
- Encrypted certificate data
- Encrypted TLS certificate
- Authentication nonce and salt
- Metadata (creation time, enrollment ID)

## Security Features

- **AES-256-GCM Encryption**: Provides confidentiality and authenticity
- **PBKDF2 Key Derivation**: 100,000 rounds with SHA-256
- **Per-user Salts**: Each user has a unique salt for key derivation
- **File Permissions**: Restricted to owner only (0700/0600)
- **Authentication**: GCM mode prevents tampering

## Development

### Loading Custom Identities

```bash
# Load identities from identities/ directory into keystore
go run scripts/load_identities_file_keystore.go ./custom_keystore_path
```

### Manual Testing

```bash
# Test the keystore directly
go run keystore/file_keystore_test.go
```
