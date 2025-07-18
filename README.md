# blockchain_api

## Session Keys

This API uses gorilla/sessions for secure session management. You must provide two secure random keys as environment variables:

- `SESSION_AUTH_KEY`: Used for session authentication/signing (32 or 64 bytes, base64 encoded)
- `SESSION_ENC_KEY`: Used for session encryption (16, 24, or 32 bytes, base64 encoded)

### Generating Keys

A helper script is provided to generate these keys and store them in a `.env` file:

```bash
bash generate_session_keys.sh
```

This will create a `.env` file with the following content:

```
SESSION_AUTH_KEY=...
SESSION_ENC_KEY=...
```

### Usage in Docker

When running your Docker container, make sure to load the `.env` file so the environment variables are available to your application:

```bash
docker run --env-file .env -p 3000:3000 your-api-image
```

> **Note:** For production, generate these keys once and keep them secret and persistent. If you generate new keys, all previous sessions will become invalid.

## Running with Docker Compose

This project uses Docker Compose profiles to separate different deployment environments:

### Available Profiles

- **`test`**: Development and testing environment with pre-loaded identities
- **`distributed`**: Production environment with separate services for each organization
- **`all`**: All services (both test and production)

### Quick Start

1. **Generate session keys** (required for all modes):
   ```bash
   bash generate_session_keys.sh
   ```

2. **Choose your deployment mode**:

   **For Development/Testing:**
   ```bash
   # Start test environment (openbao-test + blockchain-api-test)
   ./run-compose.sh test -d
   
   # Or using direct docker-compose
   docker-compose --profile test up -d
   ```

   **For Production/Distributed:**
   ```bash
   # Start distributed environment (all organization services)
   ./run-compose.sh distributed -d
   
   # Or using direct docker-compose
   docker-compose --profile distributed up -d
   ```

   **For Full Deployment:**
   ```bash
   # Start all services
   ./run-compose.sh all -d
   
   # Or using direct docker-compose
   docker-compose --profile all up -d
   ```

### Service URLs and Ports

#### Test Environment (`test` profile)
- **OpenBao Test**: http://localhost:8203 (token: `myroot`)
- **Blockchain API Test**: http://localhost:3003

#### Distributed Environment (`distributed` profile)
- **Athena Org**: 
  - OpenBao: http://localhost:8200
  - API: http://localhost:3000
- **UB Org**:
  - OpenBao: http://localhost:8201
  - API: http://localhost:3001
- **BSC Org**:
  - OpenBao: http://localhost:8202
  - API: http://localhost:3002

### Helper Script Commands

Use the provided `run-compose.sh` script for easy management:

```bash
# Start test environment
./run-compose.sh test

# Start distributed environment
./run-compose.sh distributed

# Start all services
./run-compose.sh all

# Show container status
./run-compose.sh status

# Stop all containers
./run-compose.sh stop

# Clean up everything (containers + volumes)
./run-compose.sh clean
```

### Environment Variables for Distributed Mode

For the distributed environment, set the following environment variables:

```bash
# Athena organization
export ATHENA_FABRIC_CA_URL="ca.athena.example.com"
export ATHENA_TLS_CA_URL="tls.athena.example.com"

# UB organization
export UB_FABRIC_CA_URL="ca.ub.example.com"
export UB_TLS_CA_URL="tls.ub.example.com"

# BSC organization
export BSC_FABRIC_CA_URL="ca.bsc.example.com"
export BSC_TLS_CA_URL="tls.bsc.example.com"

# Test environment
export TEST_FABRIC_CA_URL="ca.test.example.com"
export TEST_TLS_CA_URL="tls.test.example.com"
```

### Test Environment Features

The test environment includes:
- **Pre-loaded identities**: Automatically loads certificates and keys from the `./identities` folder
- **Test keystore**: OpenBao with development configuration
- **Identity verification**: Run `./scripts/test_identity_loading.sh` to verify identities are loaded correctly

### Legacy Single Service Mode

For backward compatibility, you can still run a single service:

```bash
docker-compose up --build
```

This will start only the basic services without profiles.

## Keystore Configuration

The API supports multiple keystore modes for managing cryptographic keys and certificates:

### 1. OpenBao Keystore (Recommended for Production)

OpenBao provides secure, centralized key management with authentication and access control.

- **Environment Variable**: `KEYSTORE_TYPE=openbao`
- **Configuration**: `KEYSTORE_CONFIG` should be a JSON string with OpenBao configuration

Example configuration:
```json
{
  "address": "http://openbao-athena:8200",
  "token": "your-token-here",
  "secretPath": "blockchain-keys/",
  "userPath": "auth/userpass/users/",
  "loginPath": "auth/userpass/login/"
}
```

**Production Setup with AppRole Authentication:**
```json
{
  "address": "http://openbao-athena:8200",
  "roleId": "your-role-id",
  "secretId": "your-secret-id",
  "secretPath": "blockchain-keys/",
  "userPath": "auth/userpass/users/",
  "loginPath": "auth/userpass/login/"
}
```

### 2. File-based Keystore (for testing)

The file-based keystore loads keys and certificates directly from the filesystem. This mode is designed for testing and development purposes.

- **Environment Variable**: `KEYSTORE_TYPE=file_based`
- **Configuration**: `KEYSTORE_CONFIG` should point to the base directory containing MSP structures
- **Default Path**: `./identities`

Expected directory structure:
```
identities/
├── user1/
│   └── msp/
│       ├── keystore/
│       │   └── key.pem
│       └── signcerts/
│           └── cert.pem
└── user2/
    └── msp/
        ├── keystore/
        │   └── key.pem
        └── signcerts/
            └── cert.pem
```

### Environment Variables

- `KEYSTORE_TYPE`: Type of keystore (`openbao`, `file_based`, or `remote_badger`)
- `KEYSTORE_CONFIG`: Configuration for the keystore (JSON for openbao/remote, path for file-based)
- `KEYSTORE_PASSWORD`: Password for keystore operations (required for some operations)

### OpenBao Integration

When using the Docker Compose profiles, the keystore is automatically configured:

- **Test profile**: Uses `openbao-test` with pre-loaded identities
- **Distributed profile**: Each organization uses its own OpenBao instance
- **Automatic configuration**: Environment variables are set up in docker-compose.yml

### Testing OpenBao Keystore

To verify the OpenBao keystore is working:

1. **Start test environment**:
   ```bash
   ./run-compose.sh test -d
   ```

2. **Verify identity loading**:
   ```bash
   ./scripts/test_identity_loading.sh
   ```

3. **Access OpenBao UI**:
   - URL: http://localhost:8203/ui
   - Token: `myroot`

## Scripts and Tools

The project includes several helpful scripts:

### Session Key Generation
```bash
# Generate secure session keys for gorilla/sessions
./generate_session_keys.sh
```

### Docker Compose Management
```bash
# Easy Docker Compose profile management
./run-compose.sh [mode] [options]

# Examples:
./run-compose.sh test -d        # Start test environment
./run-compose.sh distributed   # Start distributed environment
./run-compose.sh status         # Show container status
./run-compose.sh clean          # Clean up everything
```

### Identity Management (Test Environment)
```bash
# Load test identities into OpenBao (runs automatically in test mode)
./scripts/load_test_identities.sh

# Verify identities are loaded correctly
./scripts/test_identity_loading.sh

# OpenBao startup script (used internally by docker-compose)
./scripts/openbao_test_startup.sh
```

### OpenBao Operations
```bash
# Manually interact with OpenBao
export OPENBAO_ADDR="http://localhost:8203"
export OPENBAO_TOKEN="myroot"

# List stored secrets
openbao kv list kv/blockchain-keys/

# Get specific identity
openbao kv get kv/blockchain-keys/blockClient
```

## Development Workflow

### For Local Development
1. **Setup environment**:
   ```bash
   # Generate session keys
   ./generate_session_keys.sh
   
   # Start test environment
   ./run-compose.sh test -d
   ```

2. **Verify setup**:
   ```bash
   # Check container status
   ./run-compose.sh status
   
   # Test identity loading
   ./scripts/test_identity_loading.sh
   ```

3. **Develop and test**:
   - Test API: http://localhost:3003
   - OpenBao UI: http://localhost:8203/ui

4. **Cleanup**:
   ```bash
   ./run-compose.sh clean
   ```

### For Production Deployment
1. **Set environment variables**:
   ```bash
   export ATHENA_FABRIC_CA_URL="ca.athena.yourdomain.com"
   export ATHENA_TLS_CA_URL="tls.athena.yourdomain.com"
   # ... set other organization URLs
   ```

2. **Deploy distributed environment**:
   ```bash
   ./run-compose.sh distributed -d
   ```

3. **Verify deployment**:
   ```bash
   ./run-compose.sh status
   ```