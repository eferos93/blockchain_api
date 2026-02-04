# Vault Production Configuration
# Use this file when running Vault in production mode

ui = true

# Listener configuration
listener "tcp" {
  address       = "0.0.0.0:6000"
  tls_disable   = false
  tls_cert_file = "/vault/certs/vault.crt"
  tls_key_file  = "/vault/certs/vault.key"
}

# Storage backend - File storage for simplicity
# For production, consider using Consul, etcd, or cloud backends
storage "file" {
  path = "/vault/data"
}

# Disable mlock for containers (alternative: use IPC_LOCK capability)
disable_mlock = false

# API address for Vault to advertise
api_addr = "https://vault:6000"

# Cluster address (for HA setups)
cluster_addr = "https://vault:8201"

# Log level
log_level = "info"

# Telemetry (optional)
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}
