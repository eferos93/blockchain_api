package keystore_test

import (
	"testing"

	"blockchain-api/keystore"
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

func TestKeystoreInitialization(t *testing.T) {
	// Test unsupported keystore type
	err := keystore.InitializeKeystore("unsupported", "", "")
	if err == nil {
		t.Error("Should return error for unsupported keystore type")
	}
}
