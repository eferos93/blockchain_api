#!/bin/bash
# Generate secure random keys for gorilla/sessions and store them in a .env file

# Generate a 32-byte (256-bit) base64 key for authentication
SESSION_AUTH_KEY=$(head -c 32 /dev/urandom | base64)
# Generate a 32-byte (256-bit) base64 key for encryption
SESSION_ENC_KEY=$(head -c 32 /dev/urandom | base64)

cat > .env <<EOF
SESSION_AUTH_KEY=$SESSION_AUTH_KEY
SESSION_ENC_KEY=$SESSION_ENC_KEY
EOF

echo ".env file created with SESSION_AUTH_KEY and SESSION_ENC_KEY."
