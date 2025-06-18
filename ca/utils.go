package ca

import (
	"fmt"
	"os"
	"path/filepath"
)

// getProjectRoot finds the project root directory by looking for go.mod
func getProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		// Check if go.mod exists in current directory
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root directory
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("go.mod not found")
}

// extractBscRegistrarCredentials extracts certificate and private key of bscRegistrar identity for test purposes
func extractBscRegistrarCredentials() (string, string, error) {
	// Get project root
	projectRoot, err := getProjectRoot()
	if err != nil {
		return "", "", fmt.Errorf("failed to find project root: %v", err)
	}

	bscRegistrarCertPath := filepath.Join(projectRoot, "identities", "bscRegistrar", "msp", "signcerts", "cert.pem")
	bscRegistrarKeyPath := filepath.Join(projectRoot, "identities", "bscRegistrar", "msp", "keystore")

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
