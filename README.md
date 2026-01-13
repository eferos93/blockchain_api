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

This project uses Docker Compose profiles.

### Available Profiles

- **`test-filestore`**: Development and testing environment using file-based keystore

### Quick Start

1. **Generate session keys** (required):
   ```bash
   bash generate_session_keys.sh
   ```

2. **Start the environment**:

   ```bash
   # Start filestore test environment
   ./run-compose.sh test-filestore -d
   ```

### Helper Script Commands

Use the provided `run-compose.sh` script for easy management:

```bash
# Start test environment
./run-compose.sh test-filestore

# Show container status
./run-compose.sh status

# Stop all containers
./run-compose.sh stop

# Clean up everything (containers + volumes)
./run-compose.sh clean
```

### Legacy Single Service Mode

For backward compatibility, you can still run a single service:

```bash
docker-compose up --build
```

This will start only the basic services without profiles.

## Keystore Configuration

The API supports file-based keystore mode.

### File-based Keystore

The file-based keystore loads keys and certificates directly from the filesystem.

- **Environment Variable**: `KEYSTORE_TYPE=file`
- **Configuration**: `KEYSTORE_CONFIG` (JSON). Example: `{"basePath":"/app/keystore_data"}`

### Environment Variables

- `KEYSTORE_TYPE`: Type of keystore (`file`)
- `KEYSTORE_CONFIG`: Configuration for the keystore
- `KEYSTORE_PASSWORD`: Password for keystore operations

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
./run-compose.sh test-filestore -d  # Start test environment
./run-compose.sh status             # Show container status
./run-compose.sh clean              # Clean up everything
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