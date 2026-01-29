#!/bin/bash
# Script to copy identities from ../fabric/application-go-identites and run Go tests

set -e

# Check if identities directory exists and remove it
if [ -d "./identities" ]; then
    echo "Removing existing identities directory..."
    sudo rm -rf ./identities
fi

mkdir -p ./identities/

# Copy the identities folder

# I assume that the network definition is in fabric/ folder at the same level as blockchain_api
sudo cp -r ../fabric/identities/* ./identities/
sudo chown -R $USER:$USER ./identities/

echo "Identities copied. Running tests..."

# Load environment variables from .env before running tests
set -a
source .env
set +a

go test ./client -v
