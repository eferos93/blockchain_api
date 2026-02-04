package keystore

import (
	"encoding/json"
	"os"
	"testing"
)

// TestVaultKeystoreConfig tests configuration parsing
func TestVaultKeystoreConfig(t *testing.T) {
	configJSON := `{
		"address": "http://localhost:6000",
		"token": "test-token",
		"mountPath": "secret",
		"transitPath": "transit",
		"transitKey": "blockchain-api-key"
	}`

	var config VaultKeystoreConfig
	err := json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	if config.Address != "http://localhost:6000" {
		t.Errorf("Expected address 'http://localhost:6000', got '%s'", config.Address)
	}
	if config.Token != "test-token" {
		t.Errorf("Expected token 'test-token', got '%s'", config.Token)
	}
	if config.MountPath != "secret" {
		t.Errorf("Expected mountPath 'secret', got '%s'", config.MountPath)
	}
}

// TestVaultKeystoreConfigDefaults tests that defaults are applied
func TestVaultKeystoreConfigDefaults(t *testing.T) {
	configJSON := `{
		"address": "http://localhost:6000",
		"token": "test-token"
	}`

	var config VaultKeystoreConfig
	err := json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// These should be empty in config, defaults applied in NewVaultKeystore
	if config.MountPath != "" {
		t.Errorf("Expected empty mountPath before NewVaultKeystore, got '%s'", config.MountPath)
	}
}

// TestVaultKeystoreConfigValidation tests configuration validation
func TestVaultKeystoreConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      VaultKeystoreConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: VaultKeystoreConfig{
				Address: "http://localhost:6000",
				Token:   "test-token",
			},
			expectError: false,
		},
		{
			name: "missing address",
			config: VaultKeystoreConfig{
				Token: "test-token",
			},
			expectError: true,
			errorMsg:    "vault address is required",
		},
		{
			name: "missing token",
			config: VaultKeystoreConfig{
				Address: "http://localhost:6000",
			},
			expectError: true,
			errorMsg:    "vault token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewVaultKeystore(tt.config)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if err.Error() != tt.errorMsg {
					t.Errorf("Expected error '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestVaultKeystoreHashPassword tests password hashing consistency
func TestVaultKeystoreHashPassword(t *testing.T) {
	config := VaultKeystoreConfig{
		Address: "http://localhost:6000",
		Token:   "test-token",
	}

	ks, err := NewVaultKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	password := "test-password"
	hash1 := ks.hashPassword(password)
	hash2 := ks.hashPassword(password)

	if hash1 != hash2 {
		t.Error("Password hashing is not deterministic")
	}

	differentHash := ks.hashPassword("different-password")
	if hash1 == differentHash {
		t.Error("Different passwords should produce different hashes")
	}
}

// TestVaultKeystoreEncryptionContext tests encryption context generation
func TestVaultKeystoreEncryptionContext(t *testing.T) {
	config := VaultKeystoreConfig{
		Address: "http://localhost:6000",
		Token:   "test-token",
	}

	ks, err := NewVaultKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	// Same inputs should produce same context
	ctx1 := ks.createEncryptionContext("user1", "pass1")
	ctx2 := ks.createEncryptionContext("user1", "pass1")
	if string(ctx1) != string(ctx2) {
		t.Error("Encryption context is not deterministic")
	}

	// Different users should produce different contexts
	ctx3 := ks.createEncryptionContext("user2", "pass1")
	if string(ctx1) == string(ctx3) {
		t.Error("Different users should produce different contexts")
	}

	// Different passwords should produce different contexts
	ctx4 := ks.createEncryptionContext("user1", "pass2")
	if string(ctx1) == string(ctx4) {
		t.Error("Different passwords should produce different contexts")
	}
}

// TestVaultKeystoreSecretPath tests secret path generation
func TestVaultKeystoreSecretPath(t *testing.T) {
	config := VaultKeystoreConfig{
		Address:   "http://localhost:6000",
		Token:     "test-token",
		MountPath: "secret",
	}

	ks, err := NewVaultKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}

	path := ks.getSecretPath("testuser")
	expected := "secret/data/blockchain-api/users/testuser"
	if path != expected {
		t.Errorf("Expected path '%s', got '%s'", expected, path)
	}
}

// Integration tests (require running Vault instance)
// These are skipped unless VAULT_ADDR and VAULT_TOKEN are set

func TestVaultKeystoreIntegration(t *testing.T) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	if vaultAddr == "" || vaultToken == "" {
		t.Skip("Skipping integration test: VAULT_ADDR and VAULT_TOKEN not set")
	}

	config := VaultKeystoreConfig{
		Address:     vaultAddr,
		Token:       vaultToken,
		MountPath:   "secret",
		TransitPath: "transit",
		TransitKey:  "blockchain-api-test-key",
	}

	ks, err := NewVaultKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer ks.Close()

	// Test health check
	if err := ks.HealthCheck(); err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	// Test store and retrieve
	testUser := "integration-test-user"
	testPassword := "integration-test-password"
	testPrivateKey := []byte("-----BEGIN EC PRIVATE KEY-----\ntest-key\n-----END EC PRIVATE KEY-----")
	testCert := []byte("-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----")
	testTLSCert := []byte("-----BEGIN CERTIFICATE-----\ntest-tls-cert\n-----END CERTIFICATE-----")

	// Store
	err = ks.StoreKey(testUser, testPassword, testPrivateKey, testCert, testTLSCert)
	if err != nil {
		t.Fatalf("Failed to store key: %v", err)
	}

	// Retrieve
	entry, err := ks.RetrieveKey(testUser, testPassword)
	if err != nil {
		t.Fatalf("Failed to retrieve key: %v", err)
	}

	if entry.EnrollmentID != testUser {
		t.Errorf("Expected enrollment ID '%s', got '%s'", testUser, entry.EnrollmentID)
	}
	if string(entry.PrivateKey) != string(testPrivateKey) {
		t.Error("Private key mismatch")
	}
	if string(entry.Certificate) != string(testCert) {
		t.Error("Certificate mismatch")
	}
	if string(entry.TLSCertificate) != string(testTLSCert) {
		t.Error("TLS certificate mismatch")
	}

	// Test wrong password
	_, err = ks.RetrieveKey(testUser, "wrong-password")
	if err == nil {
		t.Error("Expected error with wrong password")
	}

	// Delete
	err = ks.DeleteKey(testUser, testPassword)
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify deletion
	_, err = ks.RetrieveKey(testUser, testPassword)
	if err == nil {
		t.Error("Expected error after deletion")
	}
}

func TestVaultKeystoreKeyRotation(t *testing.T) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	if vaultAddr == "" || vaultToken == "" {
		t.Skip("Skipping integration test: VAULT_ADDR and VAULT_TOKEN not set")
	}

	config := VaultKeystoreConfig{
		Address:     vaultAddr,
		Token:       vaultToken,
		MountPath:   "secret",
		TransitPath: "transit",
		TransitKey:  "blockchain-api-rotation-test-key",
	}

	ks, err := NewVaultKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer ks.Close()

	// Ensure transit key exists
	if err := ks.HealthCheck(); err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	// Store a key
	testUser := "rotation-test-user"
	testPassword := "rotation-test-password"
	testPrivateKey := []byte("-----BEGIN EC PRIVATE KEY-----\ntest-key\n-----END EC PRIVATE KEY-----")
	testCert := []byte("-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----")
	testTLSCert := []byte("-----BEGIN CERTIFICATE-----\ntest-tls-cert\n-----END CERTIFICATE-----")

	err = ks.StoreKey(testUser, testPassword, testPrivateKey, testCert, testTLSCert)
	if err != nil {
		t.Fatalf("Failed to store key: %v", err)
	}

	// Rotate the transit key
	err = ks.RotateTransitKey()
	if err != nil {
		t.Fatalf("Failed to rotate transit key: %v", err)
	}

	// Rewrap the entry with the new key version
	err = ks.RewrapEntry(testUser, testPassword)
	if err != nil {
		t.Fatalf("Failed to rewrap entry: %v", err)
	}

	// Verify data is still accessible
	entry, err := ks.RetrieveKey(testUser, testPassword)
	if err != nil {
		t.Fatalf("Failed to retrieve key after rotation: %v", err)
	}

	if string(entry.PrivateKey) != string(testPrivateKey) {
		t.Error("Private key mismatch after rotation")
	}

	// Cleanup
	ks.DeleteKey(testUser, testPassword)
}
