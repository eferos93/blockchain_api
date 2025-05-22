#!/bin/bash
# Script to copy identities from ../fabric/application-go-identites and run Go tests

set -e

# Copy the identities folder
pwd
sudo cp -r ../fabric/application-go/identities/* ./identities/

echo "Identities copied. Running tests..."

go test ./client
