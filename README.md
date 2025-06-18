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

To build and run the application using Docker Compose:

1. Make sure you have generated the `.env` file with session keys (see the Session Keys section).
2. Run the following command:

```bash
docker-compose up --build
```

This will build the Docker image and start the API service, exposing it on port 3000.

- The application will automatically use the environment variables from your `.env` file.
- To stop the service, use:

```bash
docker-compose down
```

## Keystore Configuration

The API supports two keystore modes for managing cryptographic keys and certificates:

### 1. File-based Keystore (Default - for testing)

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

### 2. Remote BadgerDB Keystore (for production)

The remote BadgerDB keystore connects to a remote BadgerDB server via HTTP API for centralized key management.

- **Environment Variable**: `KEYSTORE_TYPE=remote_badger`
- **Configuration**: `KEYSTORE_CONFIG` should be a JSON string with remote server configuration

Example configuration:
```json
{
  "serverURL": "http://badger-server:8080",
  "timeout": 30,
  "authToken": "your-auth-token"
}
```

### Environment Variables

- `KEYSTORE_TYPE`: Type of keystore (`file_based` or `remote_badger`)
- `KEYSTORE_CONFIG`: Configuration for the keystore (path for file-based, JSON for remote)
- `KEYSTORE_PASSWORD`: Password for keystore operations (required)