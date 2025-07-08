package keystore

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// OpenBaoKeystore implements KeystoreManager using OpenBao as the backend
type OpenBaoKeystore struct {
	client     *api.Client
	secretPath string // Base path for storing secrets (e.g., "secret/blockchain-keys")
}

// OpenBaoConfig contains configuration for OpenBao connection
type OpenBaoConfig struct {
	Address    string `json:"address"`    // OpenBao server address (e.g., "http://localhost:8200")
	Token      string `json:"token"`      // Authentication token
	SecretPath string `json:"secretPath"` // Base path for secrets (e.g., "secret/blockchain-keys")
}

// NewOpenBaoKeystore creates a new OpenBao keystore client
func NewOpenBaoKeystore(config OpenBaoConfig) (*OpenBaoKeystore, error) {
	if config.Address == "" {
		return nil, fmt.Errorf("address is required")
	}

	if config.Token == "" {
		return nil, fmt.Errorf("token is required")
	}

	if config.SecretPath == "" {
		config.SecretPath = "secret/blockchain-keys"
	}

	// Create OpenBao client configuration
	clientConfig := api.DefaultConfig()
	clientConfig.Address = config.Address

	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenBao client: %w", err)
	}

	// Set the authentication token
	client.SetToken(config.Token)

	return &OpenBaoKeystore{
		client:     client,
		secretPath: config.SecretPath,
	}, nil
}

// StoreKey stores an encrypted private key in OpenBao
func (o *OpenBaoKeystore) StoreKey(enrollmentID, mspID string, privateKeyPEM, certificatePEM []byte) error {
	// Create storage key from enrollmentID and mspID
	storageKey := fmt.Sprintf("%s/%s-%s", o.secretPath, mspID, enrollmentID)

	// Prepare the secret data
	secretData := map[string]any{
		"enrollmentId": enrollmentID,
		"mspId":        mspID,
		"privateKey":   base64.StdEncoding.EncodeToString(privateKeyPEM),
		"certificate":  base64.StdEncoding.EncodeToString(certificatePEM),
		"createdAt":    time.Now().Format(time.RFC3339),
	}

	// Store the secret in OpenBao
	_, err := o.client.Logical().Write(storageKey, secretData)
	if err != nil {
		return fmt.Errorf("failed to store key in OpenBao: %w", err)
	}

	return nil
}

// RetrieveKey retrieves a private key from OpenBao
func (o *OpenBaoKeystore) RetrieveKey(storageKey string) (*KeystoreEntry, error) {
	// If storageKey doesn't include the base path, construct the full path
	fullPath := storageKey
	if storageKey[0] != '/' && !contains(storageKey, o.secretPath) {
		fullPath = fmt.Sprintf("%s/%s", o.secretPath, storageKey)
	}

	// Read the secret from OpenBao
	secret, err := o.client.Logical().Read(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key from OpenBao: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("key not found: %s", storageKey)
	}

	// Parse the secret data
	entry := &KeystoreEntry{}

	if enrollmentID, ok := secret.Data["enrollmentId"].(string); ok {
		entry.EnrollmentID = enrollmentID
	}

	if mspID, ok := secret.Data["mspId"].(string); ok {
		entry.MSPID = mspID
	}

	if privateKeyB64, ok := secret.Data["privateKey"].(string); ok {
		privateKey, err := base64.StdEncoding.DecodeString(privateKeyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key: %w", err)
		}
		entry.PrivateKey = privateKey
	}

	if certificateB64, ok := secret.Data["certificate"].(string); ok {
		certificate, err := base64.StdEncoding.DecodeString(certificateB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode certificate: %w", err)
		}
		entry.Certificate = certificate
	}

	if createdAtStr, ok := secret.Data["createdAt"].(string); ok {
		createdAt, err := time.Parse(time.RFC3339, createdAtStr)
		if err == nil {
			entry.CreatedAt = createdAt
		}
	}

	return entry, nil
}

// DeleteKey removes a key from OpenBao
func (o *OpenBaoKeystore) DeleteKey(enrollmentID, mspID, storageKey string) error {
	// Determine the path to delete
	pathToDelete := storageKey
	if storageKey == "" {
		pathToDelete = fmt.Sprintf("%s/%s-%s", o.secretPath, mspID, enrollmentID)
	} else if storageKey[0] != '/' && !contains(storageKey, o.secretPath) {
		pathToDelete = fmt.Sprintf("%s/%s", o.secretPath, storageKey)
	}

	// Delete the secret from OpenBao
	_, err := o.client.Logical().Delete(pathToDelete)

	if err != nil {
		return fmt.Errorf("failed to delete key from OpenBao: %w", err)
	}

	return nil
}

// GetSalt retrieves a salt value from OpenBao
func (o *OpenBaoKeystore) GetSalt(key string) (string, error) {
	saltPath := fmt.Sprintf("%s/salts/%s", o.secretPath, key)

	secret, err := o.client.Logical().Read(saltPath)
	if err != nil {
		return "", fmt.Errorf("failed to read salt from OpenBao: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("salt not found: %s", key)
	}

	if salt, ok := secret.Data["salt"].(string); ok {
		return salt, nil
	}

	return "", fmt.Errorf("invalid salt format for key: %s", key)
}

// StoreSalt stores a salt value in OpenBao
func (o *OpenBaoKeystore) StoreSalt(key, salt string) error {
	saltPath := fmt.Sprintf("%s/salts/%s", o.secretPath, key)

	secretData := map[string]any{
		"salt":      salt,
		"createdAt": time.Now().Format(time.RFC3339),
	}

	_, err := o.client.Logical().Write(saltPath, secretData)
	if err != nil {
		return fmt.Errorf("failed to store salt in OpenBao: %w", err)
	}

	return nil
}

// Close performs cleanup (OpenBao client doesn't require explicit closing)
func (o *OpenBaoKeystore) Close() error {
	// OpenBao client doesn't require explicit closing
	return nil
}

// HealthCheck verifies OpenBao connection and authentication
func (o *OpenBaoKeystore) HealthCheck() error {
	// Check if we can read the seal status (requires basic auth)
	sealStatus, err := o.client.Sys().SealStatus()
	if err != nil {
		return fmt.Errorf("failed to connect to OpenBao: %w", err)
	}

	if sealStatus.Sealed {
		return fmt.Errorf("OpenBao is sealed")
	}

	// Try to list the secret engines to verify our token has permissions
	mounts, err := o.client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to verify OpenBao permissions: %w", err)
	}

	// Check if our secret path exists or if we can access secret engines
	if mounts == nil {
		return fmt.Errorf("unable to access OpenBao secret engines")
	}

	return nil
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && (s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
