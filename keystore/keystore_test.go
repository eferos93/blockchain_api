package keystore_test

import (
	"blockchain-api/keystore"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const (
	testPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTest1234567890ABCD
EFPrivateKeyDataHere1234567890ABCDEFhRANCAAS7mVuDjKzr4jKzr4jKzr4jKzr
4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4j
-----END PRIVATE KEY-----`

	testCertificate = `-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRATestCertificateDataHere1234567890wCgYIKoZIzj0EAwIw
czELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMT
E2NhLm9yZzEuZXhhbXBsZS5jb20wHhcNMjUwNjAxMDAwMDAwWhcNMzUwNjAxMDAw
MDAwWjBbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UE
BxMNU2FuIEZyYW5jaXNjbzEfMB0GA1UEAwwWQWRtaW5Ab3JnMS5leGFtcGxlLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ7mVuDjKzr4jKzr4jKzr4jKzr4j
Kzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4
jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr4jKzr
wCgYIKoZIzj0EAwIDSAAwRQIhATest1234567890ABCDEFSignatureDataHere1234
567890ABCDEFAiEATest1234567890ABCDEFSignatureDataHere1234567890ABCDEF
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

func TestFileBasedKeystore(t *testing.T) {
	// Create a temporary directory structure for testing
	tempDir := t.TempDir()

	// Create test MSP structure
	enrollmentID := "testuser"
	mspPath := filepath.Join(tempDir, enrollmentID, "msp")

	// Create directories
	err := os.MkdirAll(filepath.Join(mspPath, "signcerts"), 0755)
	if err != nil {
		t.Fatalf("Failed to create signcerts directory: %v", err)
	}

	err = os.MkdirAll(filepath.Join(mspPath, "keystore"), 0755)
	if err != nil {
		t.Fatalf("Failed to create keystore directory: %v", err)
	}

	// Write test certificate and key
	certPath := filepath.Join(mspPath, "signcerts", "cert.pem")
	keyPath := filepath.Join(mspPath, "keystore", "key.pem")

	err = os.WriteFile(certPath, []byte(testCertificate), 0644)
	if err != nil {
		t.Fatalf("Failed to write test certificate: %v", err)
	}

	err = os.WriteFile(keyPath, []byte(testPrivateKey), 0600)
	if err != nil {
		t.Fatalf("Failed to write test private key: %v", err)
	}

	// Test file-based keystore
	fileBased := keystore.NewFileBasedKeystore(tempDir)

	// Test RetrieveKey
	entry, err := fileBased.RetrieveKey(enrollmentID, "testMSP")
	if err != nil {
		t.Fatalf("Failed to retrieve key: %v", err)
	}

	if entry.EnrollmentID != enrollmentID {
		t.Errorf("Expected enrollment ID %s, got %s", enrollmentID, entry.EnrollmentID)
	}

	if !bytes.Equal(entry.PrivateKey, []byte(testPrivateKey)) {
		t.Errorf("Private key mismatch")
	}
	if !bytes.Equal(entry.Certificate, []byte(testCertificate)) {
		t.Errorf("Certificate mismatch")
	}

	// Test that other operations are no-ops but don't error
	err = fileBased.StoreKey("test", "testMSP", []byte("key"), []byte("cert"))
	if err != nil {
		t.Errorf("StoreKey should be no-op but returned error: %v", err)
	}

	err = fileBased.DeleteKey("test", "testMSP")
	if err != nil {
		t.Errorf("DeleteKey should be no-op but returned error: %v", err)
	}

	err = fileBased.Close()
	if err != nil {
		t.Errorf("Close should be no-op but returned error: %v", err)
	}

	err = fileBased.HealthCheck()
	if err != nil {
		t.Errorf("HealthCheck should be no-op but returned error: %v", err)
	}
}

func TestKeystoreInitialization(t *testing.T) {
	// Test file-based keystore initialization
	tempDir := t.TempDir()

	err := keystore.InitializeKeystore("file_based", tempDir, "")
	if err != nil {
		t.Fatalf("Failed to initialize file-based keystore: %v", err)
	}

	if keystore.GlobalKeystore == nil {
		t.Error("GlobalKeystore should be initialized")
	}

	// Test unsupported keystore type
	err = keystore.InitializeKeystore("unsupported", "", "")
	if err == nil {
		t.Error("Should return error for unsupported keystore type")
	}
}

func TestFileBasedKeystoreWithRealFiles(t *testing.T) {
	// Test with actual identities directory if it exists
	identitiesPath := "../identities"
	if _, err := os.Stat(identitiesPath); os.IsNotExist(err) {
		t.Skip("Skipping test - identities directory not found")
	}

	fileBased := keystore.NewFileBasedKeystore(identitiesPath)

	// Test retrieving a key that should exist
	entry, err := fileBased.RetrieveKey("blockClient", "testMSP")
	if err != nil {
		t.Logf("Could not retrieve blockClient key (expected if files don't exist): %v", err)
		return
	}

	if entry.EnrollmentID != "blockClient" {
		t.Errorf("Expected enrollment ID 'blockClient', got %s", entry.EnrollmentID)
	}

	if entry.MSPID != "testMSP" {
		t.Errorf("Expected MSP ID 'testMSP', got %s", entry.MSPID)
	}

	// Verify we got some certificate and key data
	if len(entry.Certificate) == 0 {
		t.Error("Certificate should not be empty")
	}

	if len(entry.PrivateKey) == 0 {
		t.Error("Private key should not be empty")
	}
}
