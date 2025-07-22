package keystore_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"blockchain-api/keystore"
)

// Test file keystore functionality
func TestFileKeystore_StoreAndRetrieveKey(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fileKeystore_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize file keystore
	config := keystore.FileKeystoreConfig{
		BasePath: tempDir,
		Salt:     "test-salt-for-testing",
	}

	fileKeystore, err := keystore.NewFileKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create file keystore: %v", err)
	}

	// Test data
	username := "testuser"
	password := "testsecret123"
	privateKeyPEM := []byte(testPrivateKey)
	certificatePEM := []byte(testCertificate)
	tlsCertificatePEM := []byte(testCertificate) // Using same cert for TLS for simplicity

	// Store the key
	err = fileKeystore.StoreKey(username, password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
	if err != nil {
		t.Fatalf("Failed to store key: %v", err)
	}

	// Verify user directory was created
	userDir := filepath.Join(tempDir, username)
	if _, err := os.Stat(userDir); os.IsNotExist(err) {
		t.Errorf("User directory was not created: %s", userDir)
	}

	// Verify keystore file was created
	keystoreFile := filepath.Join(userDir, "keystore.json")
	if _, err := os.Stat(keystoreFile); os.IsNotExist(err) {
		t.Errorf("Keystore file was not created: %s", keystoreFile)
	}

	// Retrieve the key with correct password
	retrievedEntry, err := fileKeystore.RetrieveKey(username, password)
	if err != nil {
		t.Fatalf("Failed to retrieve key: %v", err)
	}

	// Verify retrieved data matches stored data
	if retrievedEntry.EnrollmentID != username {
		t.Errorf("EnrollmentID mismatch: expected %s, got %s", username, retrievedEntry.EnrollmentID)
	}

	if string(retrievedEntry.PrivateKey) != string(privateKeyPEM) {
		t.Errorf("Private key mismatch")
	}

	if string(retrievedEntry.Certificate) != string(certificatePEM) {
		t.Errorf("Certificate mismatch")
	}

	if string(retrievedEntry.TLSCertificate) != string(tlsCertificatePEM) {
		t.Errorf("TLS certificate mismatch")
	}

	// Test retrieval with wrong password
	_, err = fileKeystore.RetrieveKey(username, "wrongpassword")
	if err == nil {
		t.Errorf("Should fail with wrong password")
	}
}

func TestFileKeystore_WrongPassword(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fileKeystore_wrongpassword_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize file keystore
	config := keystore.FileKeystoreConfig{
		BasePath: tempDir,
		Salt:     "test-salt-for-testing",
	}

	fileKeystore, err := keystore.NewFileKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create file keystore: %v", err)
	}

	// Store a key
	username := "testuser"
	password := "correct_password"
	privateKeyPEM := []byte(testPrivateKey)
	certificatePEM := []byte(testCertificate)
	tlsCertificatePEM := []byte(testCertificate)

	err = fileKeystore.StoreKey(username, password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
	if err != nil {
		t.Fatalf("Failed to store key: %v", err)
	}

	// Try to retrieve with wrong password
	_, err = fileKeystore.RetrieveKey(username, "wrong_password")
	if err == nil {
		t.Errorf("Should return error for wrong password")
	}

	// Verify error message indicates authentication failure
	if err != nil && !contains(err.Error(), "decrypt") {
		t.Errorf("Error should indicate decryption failure, got: %v", err)
	}
}

func TestFileKeystore_DeleteKey(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fileKeystore_delete_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize file keystore
	config := keystore.FileKeystoreConfig{
		BasePath: tempDir,
		Salt:     "test-salt-for-testing",
	}

	fileKeystore, err := keystore.NewFileKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create file keystore: %v", err)
	}

	// Store a key
	username := "testuser"
	password := "testsecret123"
	privateKeyPEM := []byte(testPrivateKey)
	certificatePEM := []byte(testCertificate)
	tlsCertificatePEM := []byte(testCertificate)

	err = fileKeystore.StoreKey(username, password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
	if err != nil {
		t.Fatalf("Failed to store key: %v", err)
	}

	// Verify key exists
	_, err = fileKeystore.RetrieveKey(username, password)
	if err != nil {
		t.Fatalf("Key should exist before deletion: %v", err)
	}

	// Delete the key
	err = fileKeystore.DeleteKey(username, password)
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify key no longer exists
	_, err = fileKeystore.RetrieveKey(username, password)
	if err == nil {
		t.Errorf("Key should not exist after deletion")
	}

	// Verify user directory was removed
	userDir := filepath.Join(tempDir, username)
	if _, err := os.Stat(userDir); !os.IsNotExist(err) {
		t.Errorf("User directory should be removed after deletion: %s", userDir)
	}

	// Test delete with wrong password
	err = fileKeystore.StoreKey(username, password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
	if err != nil {
		t.Fatalf("Failed to store key again: %v", err)
	}

	err = fileKeystore.DeleteKey(username, "wrongpassword")
	if err == nil {
		t.Errorf("Should fail to delete with wrong password")
	}
}

func TestFileKeystore_HealthCheck(t *testing.T) {
	// Test with valid directory
	tempDir, err := os.MkdirTemp("", "fileKeystore_health_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := keystore.FileKeystoreConfig{
		BasePath: tempDir,
		Salt:     "test-salt-for-testing",
	}

	fileKeystore, err := keystore.NewFileKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create file keystore: %v", err)
	}

	// Health check should pass
	err = fileKeystore.HealthCheck()
	if err != nil {
		t.Errorf("Health check should pass for valid directory: %v", err)
	}

	// Test with non-existent directory
	nonExistentConfig := keystore.FileKeystoreConfig{
		BasePath: "/non/existent/path",
		Salt:     "test-salt-for-testing",
	}

	badFileKeystore, err := keystore.NewFileKeystore(nonExistentConfig)
	if err == nil {
		// If directory creation succeeded, health check should work
		err = badFileKeystore.HealthCheck()
		if err != nil {
			t.Errorf("Health check failed unexpectedly: %v", err)
		}
	}
}

func TestFileKeystore_MultipleUsers(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fileKeystore_multiuser_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize file keystore
	config := keystore.FileKeystoreConfig{
		BasePath: tempDir,
		Salt:     "test-salt-for-testing",
	}

	fileKeystore, err := keystore.NewFileKeystore(config)
	if err != nil {
		t.Fatalf("Failed to create file keystore: %v", err)
	}

	// Store keys for multiple users
	users := []struct {
		username string
		password string
	}{
		{"user1", "password1"},
		{"user2", "password2"},
		{"user3", "password3"},
	}

	privateKeyPEM := []byte(testPrivateKey)
	certificatePEM := []byte(testCertificate)
	tlsCertificatePEM := []byte(testCertificate)

	// Store keys for all users
	for _, user := range users {
		err = fileKeystore.StoreKey(user.username, user.password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
		if err != nil {
			t.Fatalf("Failed to store key for user %s: %v", user.username, err)
		}
	}

	// Verify each user can retrieve their own key
	for _, user := range users {
		retrievedEntry, err := fileKeystore.RetrieveKey(user.username, user.password)
		if err != nil {
			t.Fatalf("Failed to retrieve key for user %s: %v", user.username, err)
		}

		if retrievedEntry.EnrollmentID != user.username {
			t.Errorf("EnrollmentID mismatch for user %s: expected %s, got %s",
				user.username, user.username, retrievedEntry.EnrollmentID)
		}
	}

	// Verify users cannot access each other's keys with wrong passwords
	_, err = fileKeystore.RetrieveKey("user1", "password2")
	if err == nil {
		t.Errorf("User should not be able to access another user's key with wrong password")
	}
}

func TestFileKeystore_Integration_WithManager(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fileKeystore_integration_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test integration with keystore manager
	config := keystore.FileKeystoreConfig{
		BasePath: tempDir,
		Salt:     "test-salt-for-integration",
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Initialize through manager
	err = keystore.InitializeKeystore("file", string(configJSON), "")
	if err != nil {
		t.Fatalf("Failed to initialize file keystore through manager: %v", err)
	}

	// Test through manager functions
	username := "integration_user"
	password := "integration_password"
	privateKeyPEM := []byte(testPrivateKey)
	certificatePEM := []byte(testCertificate)
	tlsCertificatePEM := []byte(testCertificate)

	// Store key through manager
	err = keystore.GlobalKeystore.StoreKey(username, password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
	if err != nil {
		t.Fatalf("Failed to store key through manager: %v", err)
	}

	// Retrieve key through manager
	retrievedEntry, err := keystore.GlobalKeystore.RetrieveKey(username, password)
	if err != nil {
		t.Fatalf("Failed to retrieve key through manager: %v", err)
	}

	if retrievedEntry.EnrollmentID != username {
		t.Errorf("EnrollmentID mismatch through manager: expected %s, got %s", username, retrievedEntry.EnrollmentID)
	}

	// Test manager health check
	err = keystore.GlobalKeystore.HealthCheck()
	if err != nil {
		t.Errorf("Manager health check failed: %v", err)
	}
}

func TestFileKeystore_EncryptionKeyDerivation(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "fileKeystore_encryption_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test that different salts produce different encrypted data
	config1 := keystore.FileKeystoreConfig{
		BasePath: tempDir + "/keystore1",
		Salt:     "salt1",
	}

	config2 := keystore.FileKeystoreConfig{
		BasePath: tempDir + "/keystore2",
		Salt:     "salt2",
	}

	fileKeystore1, err := keystore.NewFileKeystore(config1)
	if err != nil {
		t.Fatalf("Failed to create file keystore 1: %v", err)
	}

	fileKeystore2, err := keystore.NewFileKeystore(config2)
	if err != nil {
		t.Fatalf("Failed to create file keystore 2: %v", err)
	}

	// Store same data in both keystores
	username := "testuser"
	password := "testpassword"
	privateKeyPEM := []byte(testPrivateKey)
	certificatePEM := []byte(testCertificate)
	tlsCertificatePEM := []byte(testCertificate)

	err = fileKeystore1.StoreKey(username, password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
	if err != nil {
		t.Fatalf("Failed to store key in keystore 1: %v", err)
	}

	err = fileKeystore2.StoreKey(username, password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
	if err != nil {
		t.Fatalf("Failed to store key in keystore 2: %v", err)
	}

	// Both should be able to retrieve their own data
	entry1, err := fileKeystore1.RetrieveKey(username, password)
	if err != nil {
		t.Fatalf("Failed to retrieve from keystore 1: %v", err)
	}

	entry2, err := fileKeystore2.RetrieveKey(username, password)
	if err != nil {
		t.Fatalf("Failed to retrieve from keystore 2: %v", err)
	}

	// The plaintext should be the same
	if string(entry1.PrivateKey) != string(entry2.PrivateKey) {
		t.Errorf("Decrypted private keys should be the same")
	}

	// But the encrypted files should be different (due to different salts and nonces)
	file1, err := os.ReadFile(filepath.Join(config1.BasePath, username, "keystore.json"))
	if err != nil {
		t.Fatalf("Failed to read encrypted file 1: %v", err)
	}

	file2, err := os.ReadFile(filepath.Join(config2.BasePath, username, "keystore.json"))
	if err != nil {
		t.Fatalf("Failed to read encrypted file 2: %v", err)
	}

	if string(file1) == string(file2) {
		t.Errorf("Encrypted files should be different due to different salts")
	}
}
