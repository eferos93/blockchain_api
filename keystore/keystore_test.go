package keystore_test

import (
	"blockchain-api/keystore"
	"bytes"
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

func TestBadgerDBKeystore(t *testing.T) {
	// Create temporary directory for BadgerDB
	tempDir := t.TempDir()
	masterPassword := "test-password-123"

	// Initialize BadgerDB keystore
	ks, err := keystore.NewBadgerKeystore(tempDir, masterPassword)
	if err != nil {
		t.Fatalf("Failed to create BadgerDB keystore: %v", err)
	}
	defer ks.Close()

	// Test storing a key
	enrollmentID := "testuser"
	mspID := "Org1MSP"

	err = ks.StoreKey(enrollmentID, mspID, []byte(testPrivateKey), []byte(testCertificate))
	if err != nil {
		t.Fatalf("Failed to store key: %v", err)
	}

	// Test retrieving the key
	entry, err := ks.RetrieveKey(enrollmentID, mspID)
	if err != nil {
		t.Fatalf("Failed to retrieve key: %v", err)
	}

	// Verify data
	if entry.EnrollmentID != enrollmentID {
		t.Errorf("Expected enrollment ID %s, got %s", enrollmentID, entry.EnrollmentID)
	}
	if entry.MSPID != mspID {
		t.Errorf("Expected MSP ID %s, got %s", mspID, entry.MSPID)
	}
	if !bytes.Equal(entry.PrivateKey, []byte(testPrivateKey)) {
		t.Errorf("Private key mismatch")
	}
	if !bytes.Equal(entry.Certificate, []byte(testCertificate)) {
		t.Errorf("Certificate mismatch")
	}

	// Test listing keys
	keyIDs, err := ks.ListKeys()
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}
	if len(keyIDs) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keyIDs))
	}

	// Test deleting key
	err = ks.DeleteKey(enrollmentID, mspID)
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify key is deleted
	_, err = ks.RetrieveKey(enrollmentID, mspID)
	if err == nil {
		t.Error("Expected error when retrieving deleted key")
	}
}
