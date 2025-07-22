#!/bin/bash
# Build script for blockchain-api with dependency fixes

set -e

echo "🔧 Building blockchain-api with dependency fixes..."

# Clean everything first
echo "🧹 Cleaning build cache..."
go clean -cache -modcache -testcache
rm -f go.sum

# Force the correct versions by updating go.mod
echo "📝 Applying dependency fixes..."
go mod edit -replace=github.com/consensys/gnark-crypto=github.com/consensys/gnark-crypto@v0.12.1
go mod edit -replace=github.com/IBM/mathlib=github.com/IBM/mathlib@v0.0.3-0.20231011094432-44ee0eb539da

# Update dependencies
echo "📦 Updating dependencies..."
go mod tidy

# Download dependencies
echo "⬇️ Downloading dependencies..."
go mod download
go get github.com/consensys/bavard@latest
go get google.golang.org/genproto/googleapis/rpc/status@latest

# Build the application
echo "🏗️ Building application..."
CGO_ENABLED=0 go build -ldflags="-w -s" -o blockchain_api .

echo "✅ Build completed successfully!"
echo "🚀 You can now run: ./blockchain_api"
