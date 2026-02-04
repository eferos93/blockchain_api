package keystore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// VaultKeystore implements KeystoreManager using HashiCorp Vault
type VaultKeystore struct {
	client      *vault.Client
	mountPath   string // KV secrets engine mount path (e.g., "secret")
	transitPath string // Transit engine mount path for encryption (e.g., "transit")
	transitKey  string // Transit key name for encryption-as-a-service
	ctx         context.Context
}

// VaultKeystoreConfig contains configuration for Vault-based keystore
type VaultKeystoreConfig struct {
	Address     string          `json:"address"`             // Vault server address (e.g., "http://vault:6000")
	Token       string          `json:"token"`               // Vault authentication token
	MountPath   string          `json:"mountPath"`           // KV v2 secrets engine mount path (default: "secret")
	TransitPath string          `json:"transitPath"`         // Transit engine mount path (default: "transit")
	TransitKey  string          `json:"transitKey"`          // Transit key for encryption (default: "blockchain-api-key")
	Namespace   string          `json:"namespace"`           // Vault namespace (optional, for enterprise)
	TLSConfig   *VaultTLSConfig `json:"tlsConfig,omitempty"` // TLS configuration (optional)
}

// VaultTLSConfig contains TLS configuration for Vault connection
type VaultTLSConfig struct {
	CACert        string `json:"caCert"`        // Path to CA certificate
	CAPath        string `json:"caPath"`        // Path to directory of CA certificates
	ClientCert    string `json:"clientCert"`    // Path to client certificate
	ClientKey     string `json:"clientKey"`     // Path to client private key
	TLSServerName string `json:"tlsServerName"` // Server name for TLS verification
	Insecure      bool   `json:"insecure"`      // Skip TLS verification (not recommended for production)
}

// VaultStoredEntry represents the structure stored in Vault KV
type VaultStoredEntry struct {
	EnrollmentID     string     `json:"enrollmentId"`
	EncryptedData    string     `json:"encryptedData"`    // Base64-encoded ciphertext from Transit
	TLSEncryptedData string     `json:"tlsEncryptedData"` // Separately encrypted TLS cert
	CreatedAt        time.Time  `json:"createdAt"`
	ExpiresAt        *time.Time `json:"expiresAt,omitempty"`
}

// NewVaultKeystore creates a new Vault-based keystore
func NewVaultKeystore(config VaultKeystoreConfig) (*VaultKeystore, error) {
	if config.Address == "" {
		return nil, fmt.Errorf("vault address is required")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("vault token is required")
	}

	// Set defaults
	if config.MountPath == "" {
		config.MountPath = "secret"
	}
	if config.TransitPath == "" {
		config.TransitPath = "transit"
	}
	if config.TransitKey == "" {
		config.TransitKey = "blockchain-api-key"
	}

	// Configure Vault client
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address

	// Configure TLS if provided
	if config.TLSConfig != nil {
		tlsConfig := &vault.TLSConfig{
			CACert:        config.TLSConfig.CACert,
			CAPath:        config.TLSConfig.CAPath,
			ClientCert:    config.TLSConfig.ClientCert,
			ClientKey:     config.TLSConfig.ClientKey,
			TLSServerName: config.TLSConfig.TLSServerName,
			Insecure:      config.TLSConfig.Insecure,
		}
		if err := vaultConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	// Create Vault client
	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set token
	client.SetToken(config.Token)

	// Set namespace if provided (Vault Enterprise)
	if config.Namespace != "" {
		client.SetNamespace(config.Namespace)
	}

	vaultKeystore := &VaultKeystore{
		client:      client,
		mountPath:   config.MountPath,
		transitPath: config.TransitPath,
		transitKey:  config.TransitKey,
		ctx:         context.Background(),
	}

	return vaultKeystore, nil
}

// StoreKey stores an encrypted private key in Vault
func (v *VaultKeystore) StoreKey(username, password string, privateKeyPEM, certificatePEM, tlsCertificatePEM []byte) error {
	// Create the keystore entry
	entry := &KeystoreEntry{
		EnrollmentID:   username,
		PrivateKey:     privateKeyPEM,
		Certificate:    certificatePEM,
		TLSCertificate: tlsCertificatePEM,
		CreatedAt:      time.Now(),
	}

	// Serialize entry to JSON
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal keystore entry: %w", err)
	}

	// Encrypt using Vault Transit engine with user context (password-derived)
	encryptedData, err := v.encryptWithTransit(entryJSON, username, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt data with Transit: %w", err)
	}

	// Create stored entry
	storedEntry := &VaultStoredEntry{
		EnrollmentID:  username,
		EncryptedData: encryptedData,
		CreatedAt:     time.Now(),
	}

	// Store in Vault KV v2
	secretPath := v.getSecretPath(username)
	data := map[string]interface{}{
		"data": map[string]interface{}{
			"enrollmentId":  storedEntry.EnrollmentID,
			"encryptedData": storedEntry.EncryptedData,
			"createdAt":     storedEntry.CreatedAt.Format(time.RFC3339),
			"passwordHash":  v.hashPassword(password), // Store hash for verification
		},
	}

	_, err = v.client.Logical().Write(secretPath, data)
	if err != nil {
		return fmt.Errorf("failed to store secret in Vault: %w", err)
	}

	return nil
}

// RetrieveKey retrieves and decrypts a private key from Vault
func (v *VaultKeystore) RetrieveKey(username, password string) (*KeystoreEntry, error) {
	// Read from Vault KV v2
	secretPath := v.getSecretPath(username)
	secret, err := v.client.Logical().Read(secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no keystore entry found for user: %s", username)
	}

	// Extract data from KV v2 response
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret data format")
	}

	// Verify password hash
	storedHash, ok := data["passwordHash"].(string)
	if !ok {
		return nil, fmt.Errorf("password hash not found in stored entry")
	}
	if storedHash != v.hashPassword(password) {
		return nil, fmt.Errorf("authentication failed: invalid password")
	}

	// Get encrypted data
	encryptedData, ok := data["encryptedData"].(string)
	if !ok {
		return nil, fmt.Errorf("encrypted data not found in stored entry")
	}

	// Decrypt using Vault Transit engine
	decryptedData, err := v.decryptWithTransit(encryptedData, username, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with Transit: %w", err)
	}

	// Deserialize entry from JSON
	var entry KeystoreEntry
	if err := json.Unmarshal(decryptedData, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keystore entry: %w", err)
	}

	return &entry, nil
}

// DeleteKey removes a user's keystore entry from Vault
func (v *VaultKeystore) DeleteKey(username, password string) error {
	// Verify password first by attempting to retrieve
	_, err := v.RetrieveKey(username, password)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Delete from Vault KV v2 (metadata delete removes all versions)
	metadataPath := fmt.Sprintf("%s/metadata/blockchain-api/users/%s", v.mountPath, username)
	_, err = v.client.Logical().Delete(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to delete secret from Vault: %w", err)
	}

	return nil
}

// Close performs cleanup
func (v *VaultKeystore) Close() error {
	// Clear token for security
	v.client.ClearToken()
	return nil
}

// HealthCheck verifies that Vault is accessible and properly configured
func (v *VaultKeystore) HealthCheck() error {
	// Check Vault health
	health, err := v.client.Sys().Health()
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}

	if health.Sealed {
		return fmt.Errorf("vault is sealed")
	}

	if !health.Initialized {
		return fmt.Errorf("vault is not initialized")
	}

	// Ensure secrets engines are enabled (Transit and KV v2)
	if err := v.ensureSecretsEngines(); err != nil {
		return fmt.Errorf("secrets engine setup failed: %w", err)
	}

	// Verify Transit key exists (or create it)
	if err := v.ensureTransitKey(); err != nil {
		return fmt.Errorf("transit key verification failed: %w", err)
	}

	return nil
}

// encryptWithTransit encrypts data using Vault's Transit secrets engine
func (v *VaultKeystore) encryptWithTransit(plaintext []byte, username, password string) (string, error) {
	// Create context from username + password for additional security
	contextData := v.createEncryptionContext(username, password)

	// Encrypt using Transit
	encryptPath := fmt.Sprintf("%s/encrypt/%s", v.transitPath, v.transitKey)
	data := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		"context":   base64.StdEncoding.EncodeToString(contextData),
	}

	secret, err := v.client.Logical().Write(encryptPath, data)
	if err != nil {
		return "", fmt.Errorf("transit encryption failed: %w", err)
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("no ciphertext in transit response")
	}

	return ciphertext, nil
}

// decryptWithTransit decrypts data using Vault's Transit secrets engine
func (v *VaultKeystore) decryptWithTransit(ciphertext, username, password string) ([]byte, error) {
	// Create context from username + password (must match encryption context)
	contextData := v.createEncryptionContext(username, password)

	// Decrypt using Transit
	decryptPath := fmt.Sprintf("%s/decrypt/%s", v.transitPath, v.transitKey)
	data := map[string]interface{}{
		"ciphertext": ciphertext,
		"context":    base64.StdEncoding.EncodeToString(contextData),
	}

	secret, err := v.client.Logical().Write(decryptPath, data)
	if err != nil {
		return nil, fmt.Errorf("transit decryption failed: %w", err)
	}

	plaintextB64, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("no plaintext in transit response")
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %w", err)
	}

	return plaintext, nil
}

// ensureSecretsEngines ensures Transit and KV v2 secrets engines are enabled
func (v *VaultKeystore) ensureSecretsEngines() error {
	// Check and enable Transit secrets engine
	mounts, err := v.client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	// Enable Transit engine if not present
	transitMountPath := v.transitPath + "/"
	if _, ok := mounts[transitMountPath]; !ok {
		err = v.client.Sys().Mount(v.transitPath, &vault.MountInput{
			Type:        "transit",
			Description: "Transit secrets engine for blockchain-api encryption",
		})
		if err != nil {
			return fmt.Errorf("failed to enable transit engine: %w", err)
		}
	}

	// Enable KV v2 engine if not present
	kvMountPath := v.mountPath + "/"
	if _, ok := mounts[kvMountPath]; !ok {
		err = v.client.Sys().Mount(v.mountPath, &vault.MountInput{
			Type:        "kv",
			Description: "KV v2 secrets engine for blockchain-api storage",
			Options: map[string]string{
				"version": "2",
			},
		})
		if err != nil {
			return fmt.Errorf("failed to enable kv engine: %w", err)
		}
	}

	return nil
}

// ensureTransitKey ensures the Transit key exists, creating it if necessary
func (v *VaultKeystore) ensureTransitKey() error {
	keyPath := fmt.Sprintf("%s/keys/%s", v.transitPath, v.transitKey)

	// Check if key exists
	secret, err := v.client.Logical().Read(keyPath)
	if err != nil {
		return fmt.Errorf("failed to check transit key: %w", err)
	}

	if secret == nil {
		// Create the key with convergent encryption for derived context
		createData := map[string]interface{}{
			"type":                   "aes256-gcm96",
			"derived":                true,  // Enable key derivation
			"convergent_encryption":  true,  // Same plaintext + context = same ciphertext
			"exportable":             false, // Security: prevent key export
			"allow_plaintext_backup": false,
		}

		_, err = v.client.Logical().Write(keyPath, createData)
		if err != nil {
			return fmt.Errorf("failed to create transit key: %w", err)
		}
	}

	return nil
}

// createEncryptionContext creates a deterministic context for Transit encryption
func (v *VaultKeystore) createEncryptionContext(username, password string) []byte {
	// Create a context that combines username and password
	// This ensures that:
	// 1. Different users have different encryption contexts
	// 2. The password is required for decryption (via context matching)
	combined := fmt.Sprintf("%s:%s", username, password)
	return []byte(combined)
}

// hashPassword creates a hash of the password for verification
// Note: This is stored in Vault to verify the password before decryption
func (v *VaultKeystore) hashPassword(password string) string {
	// Use a simple hash for password verification
	// The real security comes from Transit's context-based encryption
	hash := sha256.Sum256([]byte(password))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// getSecretPath returns the KV v2 data path for a user
func (v *VaultKeystore) getSecretPath(username string) string {
	return fmt.Sprintf("%s/data/blockchain-api/users/%s", v.mountPath, username)
}

// ListUsers returns a list of all users with stored keys (admin operation)
func (v *VaultKeystore) ListUsers() ([]string, error) {
	listPath := fmt.Sprintf("%s/metadata/blockchain-api/users", v.mountPath)
	secret, err := v.client.Logical().List(listPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	users := make([]string, len(keys))
	for i, key := range keys {
		users[i] = key.(string)
	}

	return users, nil
}

// RotateTransitKey rotates the Transit encryption key (admin operation)
func (v *VaultKeystore) RotateTransitKey() error {
	rotatePath := fmt.Sprintf("%s/keys/%s/rotate", v.transitPath, v.transitKey)
	_, err := v.client.Logical().Write(rotatePath, nil)
	if err != nil {
		return fmt.Errorf("failed to rotate transit key: %w", err)
	}
	return nil
}

// RewrapEntry re-encrypts a user's data with the latest Transit key version
func (v *VaultKeystore) RewrapEntry(username, password string) error {
	// Read current entry
	secretPath := v.getSecretPath(username)
	secret, err := v.client.Logical().Read(secretPath)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return fmt.Errorf("no entry found for user: %s", username)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid secret data format")
	}

	// Verify password
	storedHash, ok := data["passwordHash"].(string)
	if !ok || storedHash != v.hashPassword(password) {
		return fmt.Errorf("authentication failed")
	}

	ciphertext, ok := data["encryptedData"].(string)
	if !ok {
		return fmt.Errorf("encrypted data not found")
	}

	// Rewrap with latest key version
	contextData := v.createEncryptionContext(username, password)
	rewrapPath := fmt.Sprintf("%s/rewrap/%s", v.transitPath, v.transitKey)
	rewrapData := map[string]interface{}{
		"ciphertext": ciphertext,
		"context":    base64.StdEncoding.EncodeToString(contextData),
	}

	rewrapSecret, err := v.client.Logical().Write(rewrapPath, rewrapData)
	if err != nil {
		return fmt.Errorf("failed to rewrap: %w", err)
	}

	newCiphertext, ok := rewrapSecret.Data["ciphertext"].(string)
	if !ok {
		return fmt.Errorf("no ciphertext in rewrap response")
	}

	// Update stored entry with new ciphertext
	updateData := map[string]interface{}{
		"data": map[string]interface{}{
			"enrollmentId":  data["enrollmentId"],
			"encryptedData": newCiphertext,
			"createdAt":     data["createdAt"],
			"passwordHash":  storedHash,
		},
	}

	_, err = v.client.Logical().Write(secretPath, updateData)
	if err != nil {
		return fmt.Errorf("failed to update rewrapped entry: %w", err)
	}

	return nil
}
