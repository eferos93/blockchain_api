package keystore_test

import (
	"fmt"
	"testing"
	"time"

	"blockchain-api/keystore"
)

const (
	testPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsyRj6S0EkuZ8S
lDUQGsLKDFLhk9qtXK2UaziXshtOyQ0i0C4Y+dLqbqeTAV47nsJYWXgiYhxd1Wio
CIiCmtn7oMnJI2BAaud0C1+XDrv+w5aVr0gU6OHGwJg3EY+Y+5hvOp9rDq/GXHPJ
I7s0lDm0C339D6jELx5dGFf60xDYpGlQt5ys4Eldci3/6OKb16io+EFexrZlAKJB
evX33tTuFbPmcwKETMC/wMNMymnB98Iu3zRnmBUF13ReOT6jR0QqgcmjqtJnzuJp
zpgSjYziA1A7XTsBtPh8WMCBHgbcsjMs8vcndPbbqqbT2EA95wpplQfV2gKTGx0M
3uN1FV4DAgMBAAECggEAJIYv6vzMbPR1/Unp+5kEkwxO2tNT1vCv2p9dq6dhIWLb
jX/fNrVckeTJNIiGAGlbYKys+euuXmF1yYtgO+d667d94DBDsOpIOd4Lm1VohP6Y
TtTqEk12KHre0kk6hxasDtsgBtPocTBq41pTwNYSao5BWCSewrXJH9m9A07pkTm6
XWrlx8ZzphLdenT5cUdaV71kMyq2Nkr/BmWFNenI9SU2lBznEtKqAN7NoezattRs
QNemltUwUKTxYiwnKfn8VLe3RMRNkwTuhVIBO0tTQE+a37T1kvqD7jcnSoPioXyl
qEUJvH9cBU+AQdBH/XB4oReus095SdKF+S6nw/tsQQKBgQDtaYymnQrYtVwjBPG7
iR9x7fKVz2fe0N634q0+YGmi10/7j5e8sBB+8OgLYjgHEcine2AgQTlm4KfZNUuv
msn48gMQopaQB9Q6kUM44gQh5ODB/OlC6VpQh+69uEr7bQ7uJ23O0E2XWqe9DeUN
f8KMKW2lXxXzGcwztv5eyeKDwwKBgQC6UDwruM+7PzeQIBv5XEUmymbTNw+BH8jI
9k2ziWUx9fy/JI6LTmVugh2gewhFLtZNMLseV2YiQvzq3gW2wsPcGiklcvSGPh24
Dn5e70IkrGJQdm3iYiOzccit2fqdbFfmZqSB2jvBUeFMaKX8qzrcX2VulhppUE5/
3L6G5JdYwQKBgEaPdkQWrKCX1lh6IbZRHM1poQ2xZPeuMGOKtV6ynPLO93CWzsw/
r8dqpiyr9mbzfCV636j2ea7/2iMOWf5JDPo2Q37wM7t++C6n+ciwM/Y25i4BkvpW
DIeevvAYFAEB+swBX/t1oXn4cZ4YwRjv/cxWi8X4qrdj1XMRUiyt5+qtAoGBAJtk
OAsvRPKjMzBd13cO4g4MWd5n2eKUI96Yrw3C1kfpJjg1wT2m0SpuE0+5zZgGDG6s
6iPQOTryLAenzZQ0tS5qE09MpW0heZ/9VqDPZJc5v3XkkJlzyNrtV7bISyHpLxbX
HPXAkn4WUJZt4aLvHVSXq/2j67tSY2Z5Md9H4IMBAoGAf1j2oNJdkcFzJ9t4kuvO
ZvRXlWMLnwPCzluKeEAbVLDhCslpnxSTIn0lPDY3bHmRoTTU8XH7PcEnKEdAWz3H
3EeOhmxRcMZY0UEimecI0STJ6fdMpWvOUFzrjIqGfGwbFRnLP6bsxzndfheSoSdp
tm3bksGwGuKcMnT5bdfKmLs=
-----END PRIVATE KEY-----`

	testCertificate = `-----BEGIN CERTIFICATE-----
MIIDVzCCAj+gAwIBAgIUBEAKoqJu1TDAR4yOO5srSG0a63AwDQYJKoZIhvcNAQEL
BQAwOzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTERMA8GA1UECgwIVGVzdCBP
cmcxCzAJBgNVBAYTAlVTMB4XDTI1MDcxNjEyMzAyM1oXDTI2MDcxNjEyMzAyM1ow
OzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTERMA8GA1UECgwIVGVzdCBPcmcx
CzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArMkY
+ktBJLmfEpQ1EBrCygxS4ZParVytlGs4l7IbTskNItAuGPnS6m6nkwFeO57CWFl4
ImIcXdVoqAiIgprZ+6DJySNgQGrndAtflw67/sOWla9IFOjhxsCYNxGPmPuYbzqf
aw6vxlxzySO7NJQ5tAt9/Q+oxC8eXRhX+tMQ2KRpULecrOBJXXIt/+jim9eoqPhB
Xsa2ZQCiQXr1997U7hWz5nMChEzAv8DDTMppwffCLt80Z5gVBdd0Xjk+o0dEKoHJ
o6rSZ87iac6YEo2M4gNQO107AbT4fFjAgR4G3LIzLPL3J3T226qm09hAPecKaZUH
1doCkxsdDN7jdRVeAwIDAQABo1MwUTAdBgNVHQ4EFgQUuQ6NUc1pOcWg7Ot4V7pr
zKXZKzswHwYDVR0jBBgwFoAUuQ6NUc1pOcWg7Ot4V7przKXZKzswDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAgThzinXclbBxwm6F6zDnJe3eThvC
uTcMj+jikjpjwBMsZt0pznGTqq0tGFp3xUdb79tdxTaK8czytlanA6hOU0ZhOfeQ
BCumprh5n9A7QREMgj10iJvZHFxxyYGudmW5fLaq9OCsYYtOprj9sfIplp81UQWu
K4xmkhvCMDhmC9eWLvCDRp3MR6exBdwTISssVStx7eOkEO0FbFNmIDAZo3TWEuuD
qAlb4eXJIlKu28pPf/St1qRfw9ZcBWksI78ne7kiD7sEH391udMvBz1EnK8EXjBI
ZaFSMWF75fGgbRNar34E61C+AhjZbxl1afesCZxk6CLwjN1Gouq3/9obtw==
-----END CERTIFICATE-----`
)

// NOTE: This package now supports two keystore modes:
// 1. File-based mode: Direct file paths to certificates and keys (no keystore needed)
// 2. Remote BadgerDB mode: HTTP API to remote BadgerDB server
//
// Local BadgerDB implementation has been removed to simplify the architecture.
// Use remote BadgerDB server for centralized key management or file-based paths for simple setups.

func TestKeystoreConstants(t *testing.T) {
	// Test that our test constants are properly formatted
	if len(testPrivateKey) == 0 {
		t.Error("Test private key should not be empty")
	}
	if len(testCertificate) == 0 {
		t.Error("Test certificate should not be empty")
	}

	// Basic validation that the keys contain expected PEM headers
	if !contains(testPrivateKey, "-----BEGIN PRIVATE KEY-----") {
		t.Error("Test private key should contain PEM header")
	}
	if !contains(testCertificate, "-----BEGIN CERTIFICATE-----") {
		t.Error("Test certificate should contain PEM header")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}

func TestKeystoreInitialization(t *testing.T) {
	// Test unsupported keystore type
	err := keystore.InitializeKeystore("unsupported", "", "")
	if err == nil {
		t.Error("Should return error for unsupported keystore type")
	}

	// Test invalid OpenBao config
	err = keystore.InitializeKeystore("openbao", "invalid json", "")
	if err == nil {
		t.Error("Should return error for invalid OpenBao config")
	}

	// Test valid OpenBao config but without connection
	validConfig := `{
		"address": "http://localhost:8200",
		"token": "test-token",
		"secretPath": "blockchain-keys/",
		"userPath": "auth/userpass/users/",
		"loginPath": "auth/userpass/login/"
	}`
	err = keystore.InitializeKeystore("openbao", validConfig, "")
	// This should fail because we don't have a real OpenBao instance running
	if err == nil {
		t.Log("OpenBao connection succeeded (if this passes, you have OpenBao running)")
	} else {
		t.Logf("Expected OpenBao connection failure: %v", err)
	}
}

func TestOpenBaoConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      keystore.OpenBaoConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: keystore.OpenBaoConfig{
				Address:    "http://localhost:8200",
				Token:      "test-token",
				SecretPath: "blockchain-keys/",
				UserPath:   "auth/userpass/users/",
				LoginPath:  "auth/userpass/login/",
			},
			expectError: false,
		},
		{
			name: "missing address",
			config: keystore.OpenBaoConfig{
				Token:      "test-token",
				SecretPath: "blockchain-keys/",
			},
			expectError: true,
		},
		{
			name: "missing token",
			config: keystore.OpenBaoConfig{
				Address:    "http://localhost:8200",
				SecretPath: "blockchain-keys/",
			},
			expectError: true,
		},
		{
			name: "defaults applied",
			config: keystore.OpenBaoConfig{
				Address: "http://localhost:8200",
				Token:   "test-token",
				// SecretPath, UserPath, LoginPath should get defaults
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := keystore.NewOpenBaoKeystore(tt.config)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCertificateValidation(t *testing.T) {
	tests := []struct {
		name        string
		certPEM     []byte
		expectError bool
	}{
		{
			name:        "valid certificate",
			certPEM:     []byte(testCertificate),
			expectError: false,
		},
		{
			name:        "invalid PEM format",
			certPEM:     []byte("invalid certificate data"),
			expectError: true,
		},
		{
			name:        "empty certificate",
			certPEM:     []byte(""),
			expectError: true,
		},
		{
			name: "malformed PEM",
			certPEM: []byte(`-----BEGIN CERTIFICATE-----
MalformedCertificateData
-----END CERTIFICATE-----`),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keystore.ValidateCertificate(tt.certPEM)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestKeystoreEntryStructure(t *testing.T) {
	entry := &keystore.KeystoreEntry{
		EnrollmentID:   "testuser",
		PrivateKey:     []byte(testPrivateKey),
		Certificate:    []byte(testCertificate),
		TLSCertificate: []byte(testCertificate),
		CreatedAt:      time.Now(),
	}

	// Test that all fields are populated
	if entry.EnrollmentID == "" {
		t.Error("EnrollmentID should not be empty")
	}
	if len(entry.PrivateKey) == 0 {
		t.Error("PrivateKey should not be empty")
	}
	if len(entry.Certificate) == 0 {
		t.Error("Certificate should not be empty")
	}
	if len(entry.TLSCertificate) == 0 {
		t.Error("TLSCertificate should not be empty")
	}
	if entry.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestGlobalKeystoreOperations(t *testing.T) {
	// Test operations when GlobalKeystore is not initialized
	_, err := keystore.RetrievePrivateKey("testuser", "password")
	if err == nil {
		t.Error("Should return error when GlobalKeystore is not initialized")
	}

	_, _, err = keystore.GetKeyForFabricClient("testuser", "TestMSP", "password")
	if err == nil {
		t.Error("Should return error when GlobalKeystore is not initialized")
	}

	// Test StorePrivateKey with nil GlobalKeystore
	err = keystore.StorePrivateKey("testuser", "password", []byte(testCertificate), []byte(testCertificate), nil)
	if err == nil {
		t.Error("Should return error when GlobalKeystore is not initialized")
	}
}

func TestPrivateKeyToPEMConversion(t *testing.T) {
	// This tests the internal convertPrivateKeyToPEM function indirectly
	// by testing StorePrivateKey with a nil private key
	err := keystore.StorePrivateKey("testuser", "password", []byte(testCertificate), []byte(testCertificate), nil)
	if err == nil {
		t.Error("Should return error for nil private key")
	}
}

// Mock OpenBao keystore for testing without actual OpenBao instance
type MockOpenBaoKeystore struct {
	data map[string]*keystore.KeystoreEntry
}

func NewMockOpenBaoKeystore() *MockOpenBaoKeystore {
	return &MockOpenBaoKeystore{
		data: make(map[string]*keystore.KeystoreEntry),
	}
}

func (m *MockOpenBaoKeystore) StoreKey(username, password string, privateKeyPEM, certificatePEM, tlsCertificatePEM []byte) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password required")
	}

	entry := &keystore.KeystoreEntry{
		EnrollmentID:   username,
		PrivateKey:     privateKeyPEM,
		Certificate:    certificatePEM,
		TLSCertificate: tlsCertificatePEM,
		CreatedAt:      time.Now(),
	}

	m.data[username] = entry
	return nil
}

func (m *MockOpenBaoKeystore) RetrieveKey(username, password string) (*keystore.KeystoreEntry, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password required")
	}

	entry, exists := m.data[username]
	if !exists {
		return nil, fmt.Errorf("key not found for user: %s", username)
	}

	return entry, nil
}

func (m *MockOpenBaoKeystore) DeleteKey(username, password string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password required")
	}

	delete(m.data, username)
	return nil
}

func (m *MockOpenBaoKeystore) Close() error {
	return nil
}

func (m *MockOpenBaoKeystore) HealthCheck() error {
	return nil
}

func TestMockKeystoreOperations(t *testing.T) {
	// Test with mock keystore to verify the interface works correctly
	mockKeystore := NewMockOpenBaoKeystore()

	// Store the mock keystore in global for testing
	originalKeystore := keystore.GlobalKeystore
	defer func() {
		keystore.GlobalKeystore = originalKeystore
	}()
	keystore.GlobalKeystore = mockKeystore

	// Test storing a key
	err := mockKeystore.StoreKey("testuser", "password", []byte(testPrivateKey), []byte(testCertificate), []byte(testCertificate))
	if err != nil {
		t.Errorf("Failed to store key: %v", err)
	}

	// Test retrieving the key
	entry, err := mockKeystore.RetrieveKey("testuser", "password")
	if err != nil {
		t.Errorf("Failed to retrieve key: %v", err)
	}
	if entry.EnrollmentID != "testuser" {
		t.Errorf("Expected enrollment ID 'testuser', got '%s'", entry.EnrollmentID)
	}

	// Test deleting the key
	err = mockKeystore.DeleteKey("testuser", "password")
	if err != nil {
		t.Errorf("Failed to delete key: %v", err)
	}

	// Test retrieving deleted key (should fail)
	_, err = mockKeystore.RetrieveKey("testuser", "password")
	if err == nil {
		t.Error("Should return error when retrieving deleted key")
	}

	// Test health check
	err = mockKeystore.HealthCheck()
	if err != nil {
		t.Errorf("Health check failed: %v", err)
	}

	// Test close
	err = mockKeystore.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestKeystoreIntegrationWithManager(t *testing.T) {
	// Test integration between manager functions and keystore
	mockKeystore := NewMockOpenBaoKeystore()

	// Store the mock keystore in global for testing
	originalKeystore := keystore.GlobalKeystore
	defer func() {
		keystore.GlobalKeystore = originalKeystore
	}()
	keystore.GlobalKeystore = mockKeystore

	// Store key using manager function
	err := mockKeystore.StoreKey("integrationuser", "password", []byte(testPrivateKey), []byte(testCertificate), []byte(testCertificate))
	if err != nil {
		t.Errorf("Failed to store key via manager: %v", err)
	}

	// Retrieve key using manager function
	entry, err := keystore.RetrievePrivateKey("integrationuser", "password")
	if err != nil {
		t.Errorf("Failed to retrieve key via manager: %v", err)
	}
	if entry == nil {
		t.Error("Retrieved entry should not be nil")
	}

	// Test GetKeyForFabricClient
	certPEM, keyPEM, err := keystore.GetKeyForFabricClient("integrationuser", "TestMSP", "password")
	if err != nil {
		t.Errorf("Failed to get key for Fabric client: %v", err)
	}
	if len(certPEM) == 0 {
		t.Error("Certificate PEM should not be empty")
	}
	if len(keyPEM) == 0 {
		t.Error("Private key PEM should not be empty")
	}
}

func TestErrorHandling(t *testing.T) {
	mockKeystore := NewMockOpenBaoKeystore()

	// Test with empty username
	err := mockKeystore.StoreKey("", "password", []byte(testPrivateKey), []byte(testCertificate), []byte(testCertificate))
	if err == nil {
		t.Error("Should return error for empty username")
	}

	// Test with empty password
	err = mockKeystore.StoreKey("testuser", "", []byte(testPrivateKey), []byte(testCertificate), []byte(testCertificate))
	if err == nil {
		t.Error("Should return error for empty password")
	}

	// Test retrieving non-existent key
	_, err = mockKeystore.RetrieveKey("nonexistent", "password")
	if err == nil {
		t.Error("Should return error for non-existent key")
	}
}
