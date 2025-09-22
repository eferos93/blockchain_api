#!/bin/bash
# Script to copy identities from ../fabric/application-go-identites and run Go tests

set -e

mkdir -p ./identities/

# Copy the identities folder

# I suppose that the network definition is in fabric/ folder at the same level as blockchain_api
sudo cp -r ../fabric/identities/* ./identities/
sudo chown -R $USER:$USER ./identities/

echo "Identities copied. Running tests..."

# Load environment variables from .env before running tests
set -a
source .env
set +a

go test ./client -v
