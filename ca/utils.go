package ca

import (
	"fmt"
	"os"
	"path/filepath"
)

// extractBscRegistrarCredentials extracts certificate and private key of bscRegistrar identity for test purposes
func extractBscRegistrarCredentials() (string, string, error) {
	bscRegistrarCertPath := "./identities/bscRegistrar/msp/signcerts/cert.pem"
	bscRegistrarKeyPath := "./identities/bscRegistrar/msp/keystore"

	// Read certificate
	certBytes, err := os.ReadFile(bscRegistrarCertPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read bscRegistrar certificate: %v", err)
	}

	// Read private key (first file in keystore directory)
	keyFiles, err := os.ReadDir(bscRegistrarKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read bscRegistrar keystore directory: %v", err)
	}

	if len(keyFiles) == 0 {
		return "", "", fmt.Errorf("no private key found in bscRegistrar keystore directory")
	}

	keyBytes, err := os.ReadFile(filepath.Join(bscRegistrarKeyPath, keyFiles[0].Name()))
	if err != nil {
		return "", "", fmt.Errorf("failed to read bscRegistrar private key: %v", err)
	}

	return string(certBytes), string(keyBytes), nil
}
