#!/bin/bash

# Script to load test identities into OpenBao keystore
# This script is designed to run after OpenBao is started and ready

set -e

# Configuration
OPENBAO_ADDR=${OPENBAO_ADDR:-"http://localhost:8200"}
OPENBAO_TOKEN=${OPENBAO_TOKEN:-"myroot"}
IDENTITIES_PATH=${IDENTITIES_PATH:-"/identities"}
SECRET_BASE_PATH=${SECRET_BASE_PATH:-"blockchain-keys"}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Wait for OpenBao to be ready
wait_for_openbao() {
    log_info "Waiting for OpenBao to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -f "${OPENBAO_ADDR}/v1/sys/health" > /dev/null 2>&1; then
            log_success "OpenBao is ready!"
            return 0
        fi
        
        log_info "Attempt ${attempt}/${max_attempts}: OpenBao not ready yet, waiting 2 seconds..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    log_error "OpenBao failed to become ready after ${max_attempts} attempts"
    return 1
}

# Function to create user in OpenBao userpass auth
create_user() {
    local username="$1"
    local password="$2"
    
    log_info "Creating user: $username"
    
    # Enable userpass auth method if not already enabled
    curl -s -X POST \
        -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"type":"userpass"}' \
        "${OPENBAO_ADDR}/v1/sys/auth/userpass" 2>/dev/null || true
    
    # Create the user
    local response=$(curl -s -w "%{http_code}" -X POST \
        -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"password\":\"${password}\"}" \
        "${OPENBAO_ADDR}/v1/auth/userpass/users/${username}")
    
    local http_code="${response: -3}"
    if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
        log_success "User $username created successfully"
    else
        log_warning "Failed to create user $username (HTTP: $http_code)"
    fi
}

# Function to store identity in OpenBao
store_identity() {
    local identity_name="$1"
    local private_key_path="$2"
    local certificate_path="$3"
    local tls_cert_path="$4"
    local password="$5"
    
    log_info "Processing identity: $identity_name"
    
    # Check if all files exist
    if [[ ! -f "$private_key_path" ]]; then
        log_error "Private key not found: $private_key_path"
        return 1
    fi
    
    if [[ ! -f "$certificate_path" ]]; then
        log_error "Certificate not found: $certificate_path"
        return 1
    fi
    
    if [[ ! -f "$tls_cert_path" ]]; then
        log_error "TLS certificate not found: $tls_cert_path"
        return 1
    fi
    
    # Read and encode files
    local private_key_b64=$(base64 -w 0 "$private_key_path")
    local certificate_b64=$(base64 -w 0 "$certificate_path")
    local tls_cert_b64=$(base64 -w 0 "$tls_cert_path")
    local created_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Create user first
    create_user "$identity_name" "$password"
    
    # Prepare JSON payload
    local json_payload=$(cat <<EOF
{
  "data": {
    "enrollmentId": "$identity_name",
    "privateKey": "$private_key_b64",
    "certificate": "$certificate_b64",
    "tlsCertificate": "$tls_cert_b64",
    "createdAt": "$created_at"
  }
}
EOF
)
    
    # Store in OpenBao KV store
    local response=$(curl -s -w "%{http_code}" -X POST \
        -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        "${OPENBAO_ADDR}/v1/kv/data/${SECRET_BASE_PATH}/${identity_name}")
    
    local http_code="${response: -3}"
    if [ "$http_code" = "200" ] || [ "$http_code" = "204" ]; then
        log_success "Identity $identity_name stored successfully"
    else
        log_error "Failed to store identity $identity_name (HTTP: $http_code)"
        echo "Response: ${response%???}"
        return 1
    fi
}

# Function to process identity folder
process_identity_folder() {
    local folder_path="$1"
    local identity_name=$(basename "$folder_path")
    
    log_info "Processing identity folder: $identity_name"
    
    # Look for MSP structure first
    local msp_path="$folder_path/msp"
    if [[ -d "$msp_path" ]]; then
        local private_key_path="$msp_path/keystore/key.pem"
        local certificate_path="$msp_path/signcerts/cert.pem"
        local tls_cert_path="$msp_path/tlscacerts/ca.crt"
        
        # Use a default password based on identity name
        local password="${identity_name}password"
        
        store_identity "$identity_name" "$private_key_path" "$certificate_path" "$tls_cert_path" "$password"
    else
        log_warning "No MSP folder found in $folder_path, skipping..."
    fi
}

# Main function
main() {
    log_info "Starting OpenBao test identity loader..."
    log_info "OpenBao Address: $OPENBAO_ADDR"
    log_info "Identities Path: $IDENTITIES_PATH"
    log_info "Secret Base Path: $SECRET_BASE_PATH"
    
    # Wait for OpenBao to be ready
    if ! wait_for_openbao; then
        log_error "OpenBao is not available, exiting..."
        exit 1
    fi
    
    # Enable KV v2 secrets engine if not already enabled
    log_info "Enabling KV v2 secrets engine..."
    curl -s -X POST \
        -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{"type":"kv","options":{"version":"2"}}' \
        "${OPENBAO_ADDR}/v1/sys/mounts/kv" 2>/dev/null || log_info "KV engine already enabled or failed to enable"
    
    # Process each identity folder
    if [[ ! -d "$IDENTITIES_PATH" ]]; then
        log_error "Identities path does not exist: $IDENTITIES_PATH"
        exit 1
    fi
    
    local processed_count=0
    local failed_count=0
    
    for identity_folder in "$IDENTITIES_PATH"/*; do
        if [[ -d "$identity_folder" ]]; then
            # Skip TLS root cert folders
            if [[ "$(basename "$identity_folder")" == *"TLS-root-cert" ]]; then
                log_info "Skipping TLS root cert folder: $(basename "$identity_folder")"
                continue
            fi
            
            if process_identity_folder "$identity_folder"; then
                processed_count=$((processed_count + 1))
            else
                failed_count=$((failed_count + 1))
            fi
        fi
    done
    
    log_info "Identity loading completed!"
    log_success "Successfully processed: $processed_count identities"
    if [ $failed_count -gt 0 ]; then
        log_warning "Failed to process: $failed_count identities"
    fi
    
    # List stored secrets for verification
    log_info "Listing stored identities for verification..."
    curl -s -X GET \
        -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
        "${OPENBAO_ADDR}/v1/kv/metadata/${SECRET_BASE_PATH}?list=true" | \
        grep -o '"[^"]*"' | grep -v '"keys"' | sort || log_info "No identities found or failed to list"
}

# Run main function
main "$@"
