# OpenBao Test Identity Loading

This directory contains scripts for automatically loading test identities into the OpenBao keystore when running the `openbao-test` container.

## Scripts

### `openbao_test_startup.sh`
Main startup script for the `openbao-test` container. This script:
1. Starts OpenBao in development mode
2. Waits for OpenBao to be ready
3. Automatically loads test identities from the `/identities` folder
4. Handles graceful shutdown

### `load_test_identities.sh`
Identity loading script that:
1. Scans the `/identities` folder for identity directories
2. Extracts private keys, certificates, and TLS certificates from each identity
3. Creates users in OpenBao's userpass authentication method
4. Stores the cryptographic material in OpenBao's KV store
5. Provides detailed logging and error handling

### `test_identity_loading.sh`
Test script to verify that identities were loaded correctly:
1. Checks OpenBao connectivity
2. Lists all stored identities
3. Tests retrieval of identity data
4. Validates the stored data structure

## Usage

### Running the test container
```bash
# Start the openbao-test container
docker-compose up openbao-test

# Or start all services
docker-compose up -d
```

### Testing identity loading
```bash
# Wait for the container to be fully started, then run:
./scripts/test_identity_loading.sh
```

### Manual identity loading
```bash
# If you need to reload identities manually:
docker-compose exec openbao-test /scripts/load_test_identities.sh
```

## Identity Structure Expected

The script expects identities to be organized as follows:
```
identities/
├── blockClient/
│   └── msp/
│       ├── keystore/
│       │   └── key.pem          # Private key
│       ├── signcerts/
│       │   └── cert.pem         # Certificate
│       └── tlscacerts/
│           └── ca.crt           # TLS CA certificate
├── bscRegistrar/
│   └── msp/
│       └── [same structure]
└── [other identities...]
```

## Environment Variables

- `OPENBAO_ADDR`: OpenBao server address (default: http://localhost:8200)
- `OPENBAO_TOKEN`: OpenBao root token (default: myroot)
- `IDENTITIES_PATH`: Path to identities folder (default: /identities)
- `SECRET_BASE_PATH`: Base path for storing secrets (default: blockchain-keys)

## Default Passwords

For each identity, the script creates a user with the password format: `{identity_name}password`

Examples:
- blockClient -> password: `blockClientpassword`
- bscRegistrar -> password: `bscRegistrarpassword`

## Stored Data Format

Each identity is stored in OpenBao with the following structure:
```json
{
  "enrollmentId": "blockClient",
  "privateKey": "base64_encoded_private_key",
  "certificate": "base64_encoded_certificate", 
  "tlsCertificate": "base64_encoded_tls_certificate",
  "createdAt": "2025-07-17T12:30:23Z"
}
```

## Accessing Stored Identities

You can access the identities through:

1. **OpenBao UI**: http://localhost:8203/ui (token: myroot)
2. **API**: Using the test script or curl commands
3. **Your Go application**: Using the keystore manager

## Troubleshooting

### Container won't start
- Check that the scripts are executable
- Ensure the identities folder exists and has the correct structure
- Check Docker logs: `docker-compose logs openbao-test`

### Identities not loading
- Run the test script to see detailed error messages
- Check that certificate files are valid PEM format
- Verify file permissions allow reading the identity files

### Connection issues
- Ensure OpenBao is fully started before running tests
- Check that port 8203 is not blocked by firewall
- Verify the container is running: `docker-compose ps`
