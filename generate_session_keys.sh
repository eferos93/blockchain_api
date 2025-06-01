#!/bin/bash
# Generate secure random keys for gorilla/sessions and store them in a .env file

# Generate a 32-byte (256-bit) hex key for authentication
SESSION_AUTH_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)
# Generate a 32-byte (256-bit) hex key for encryption
SESSION_ENC_KEY=$(head -c 32 /dev/urandom | xxd -p -c 32)
# Generate keystore password
KEYSTORE_PASSWORD=$(head -c 32 /dev/urandom | xxd -p -c 32)

cat > .env <<EOF
SESSION_AUTH_KEY=$SESSION_AUTH_KEY
SESSION_ENC_KEY=$SESSION_ENC_KEY
KEYSTORE_TYPE=file
KEYSTORE_CONFIG=./secure-keystore
KEYSTORE_PASSWORD=$KEYSTORE_PASSWORD
EOF

echo ".env file created with SESSION_AUTH_KEY, SESSION_ENC_KEY, and KEYSTORE_PASSWORD."
