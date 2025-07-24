# TLS Configuration for Fabric CA Client

## Overview

The blockchain API can connect to Fabric CA servers using either:
1. **Development Mode**: Skip TLS verification (`SkipTLS: true`)
2. **Production Mode**: Secure TLS with certificate validation (`SkipTLS: false`)

## Environment Variables

### Fabric CA Configuration
- `FABRIC_CA_URL` - CA server URL (default: `https://localhost:10055`)
- `FABRIC_CA_NAME` - CA name (default: `ca-bsc`)
- `FABRIC_CA_MSPID` - MSP ID (default: `BscMSP`)
- `FABRIC_CA_TLS_CERTS` - Path to CA TLS certificates (optional)
- `FABRIC_CA_SKIP_TLS` - Skip TLS verification (default: `true`)

### TLS CA Configuration
- `TLS_CA_URL` - TLS CA server URL (default: `https://localhost:10054`)
- `TLS_CA_NAME` - TLS CA name (default: `tlsca-bsc`)
- `TLS_CA_MSPID` - MSP ID (default: `BscMSP`)
- `TLS_CA_TLS_CERTS` - Path to TLS CA certificates (optional)
- `TLS_CA_SKIP_TLS` - Skip TLS verification (default: `true`)

## Setting Up Secure TLS

### 1. Prepare CA Certificates

For production environments, you need the CA certificates that signed the Fabric CA server's TLS certificate.

#### Option A: Single Certificate File
```bash
# Place all CA certificates in a single PEM file
cat ca-cert.pem intermediate-cert.pem > /path/to/ca-certs.pem
```

#### Option B: Certificate Directory
```bash
# Place certificates in a directory
mkdir -p /path/to/ca-certs/
cp ca-cert.pem /path/to/ca-certs/
cp intermediate-cert.pem /path/to/ca-certs/
```

### 2. Configure Environment Variables

#### For Single Certificate File:
```bash
export FABRIC_CA_SKIP_TLS=false
export FABRIC_CA_TLS_CERTS=/path/to/ca-certs.pem
export TLS_CA_SKIP_TLS=false
export TLS_CA_TLS_CERTS=/path/to/ca-certs.pem
```

#### For Certificate Directory:
```bash
export FABRIC_CA_SKIP_TLS=false
export FABRIC_CA_TLS_CERTS=/path/to/ca-certs/
export TLS_CA_SKIP_TLS=false
export TLS_CA_TLS_CERTS=/path/to/ca-certs/
```

#### For System CA Certificates:
```bash
# Use system's default CA certificates
export FABRIC_CA_SKIP_TLS=false
# Don't set FABRIC_CA_TLS_CERTS (empty means use system certs)
export TLS_CA_SKIP_TLS=false
# Don't set TLS_CA_TLS_CERTS (empty means use system certs)
```

### 3. Docker Configuration

#### Using Docker Run:
```bash
docker run -d \
  -e FABRIC_CA_SKIP_TLS=false \
  -e FABRIC_CA_TLS_CERTS=/app/ca-certs \
  -e TLS_CA_SKIP_TLS=false \
  -e TLS_CA_TLS_CERTS=/app/ca-certs \
  -v /host/path/to/ca-certs:/app/ca-certs:ro \
  blockchain-api
```

#### Using Docker Compose:
```yaml
version: '3.8'
services:
  blockchain-api:
    build: .
    environment:
      - FABRIC_CA_SKIP_TLS=false
      - FABRIC_CA_TLS_CERTS=/app/ca-certs
      - TLS_CA_SKIP_TLS=false
      - TLS_CA_TLS_CERTS=/app/ca-certs
    volumes:
      - ./ca-certs:/app/ca-certs:ro
```

## Certificate File Formats

The TLS configuration supports:
- **File extensions**: `.pem`, `.crt`, `.cert`
- **Content**: X.509 certificates in PEM format
- **Multiple certificates**: Multiple certificates in a single file or multiple files in a directory

### Example Certificate File:
```
-----BEGIN CERTIFICATE-----
MIICXTCCAcagAwIBAgIBADANBgkqhkiG9w0BAQsFADA...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICYTCCAcugAwIBAgIBATANBgkqhkiG9w0BAQsFADA...
-----END CERTIFICATE-----
```

## TLS Security Features

When `SkipTLS=false`, the following security measures are enforced:

1. **Minimum TLS Version**: TLS 1.2 or higher
2. **Certificate Validation**: Server certificates must be signed by trusted CAs
3. **Hostname Verification**: Server hostname must match certificate
4. **Custom CA Support**: Load custom CA certificates if provided
5. **System CA Fallback**: Use system CA certificates if no custom CAs specified

## Troubleshooting

### Common Issues:

1. **Certificate Verification Failed**
   ```
   Error: x509: certificate signed by unknown authority
   ```
   **Solution**: Ensure CA certificates are properly configured

2. **Hostname Mismatch**
   ```
   Error: x509: certificate is valid for localhost, not ca.example.com
   ```
   **Solution**: Use correct hostname in CA URL or add hostname to certificate

3. **TLS Handshake Failure**
   ```
   Error: remote error: tls: handshake failure
   ```
   **Solution**: Check TLS version compatibility and cipher suites

### Debug Mode:
Set environment variable for verbose TLS debugging:
```bash
export GODEBUG=x509verifier=1
```

## Example: Hyperledger Fabric Test Network

For the Fabric test network, CA certificates are typically located at:
```
test-network/organizations/fabric-ca/org1/ca-cert.pem
test-network/organizations/fabric-ca/org2/ca-cert.pem
```

Configuration:
```bash
export FABRIC_CA_SKIP_TLS=false
export FABRIC_CA_TLS_CERTS=./test-network/organizations/fabric-ca/org1/ca-cert.pem
export TLS_CA_SKIP_TLS=false
export TLS_CA_TLS_CERTS=./test-network/organizations/fabric-ca/org1/ca-cert.pem
```
