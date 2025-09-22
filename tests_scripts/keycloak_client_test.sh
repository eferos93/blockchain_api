#!/bin/bash


# -e: exit immediately if any command returns a non‑zero status.

set -e

# Args: path to test file
TESTFILE=keycloak/keycloak_test.go

# Load environment variables from .env before running tests
set -a
source .env
set +a

# Example: verbose, run all in file
go test -v $TESTFILE
