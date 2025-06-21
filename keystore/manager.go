package keystore

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// GlobalKeystore is the application-wide keystore instance
var GlobalKeystore KeystoreManager

// InitializeKeystore initializes the global keystore
func InitializeKeystore(keystoreType, config, masterPassword string) error {
	switch keystoreType {
	case "remote_badger":
		// Remote BadgerDB keystore via HTTP API
		var remoteBadgerConfig RemoteBadgerConfig
		if err := json.Unmarshal([]byte(config), &remoteBadgerConfig); err != nil {
			return fmt.Errorf("failed to parse remote BadgerDB config: %w", err)
		}

		remoteDB, err := NewRemoteBadgerKeystore(remoteBadgerConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize remote BadgerDB keystore: %w", err)
		}

		// Test connection
		if err := remoteDB.HealthCheck(); err != nil {
			return fmt.Errorf("remote BadgerDB health check failed: %w", err)
		}

		GlobalKeystore = remoteDB
	case "badger_test":
		// Legacy test case - use local BadgerDB
		db, err := NewBadgerKeystore(config, masterPassword)
		if err != nil {
			return fmt.Errorf("failed to initialize BadgerDB keystore: %w", err)
		}
		GlobalKeystore = db
	default:
		return fmt.Errorf("unsupported keystore type: %s (supported: badger, remote_badger)", keystoreType)
	}
	return nil
}

// StoreEnrollmentResult stores the results from CA enrollment
func StoreEnrollmentResult(enrollmentID, mspID string, enrollmentResult map[string]interface{}) error {
	if GlobalKeystore == nil {
		return fmt.Errorf("keystore not initialized")
	}

	// Extract certificate and private key from enrollment result
	cert, ok := enrollmentResult["Cert"].(string)
	if !ok {
		return fmt.Errorf("certificate not found in enrollment result")
	}

	// Some CA servers return the private key, others require it to be generated client-side
	privateKey, hasPrivateKey := enrollmentResult["PrivateKey"].(string)
	if !hasPrivateKey {
		return fmt.Errorf("private key not found in enrollment result")
	}

	return GlobalKeystore.StoreKey(enrollmentID, mspID, privateKey, cert)
}

// CreateMSPStructure creates traditional Fabric MSP folder structure from keystore
func CreateMSPStructure(enrollmentID, mspID, outputPath string) error {
	if GlobalKeystore == nil {
		return fmt.Errorf("keystore not initialized")
	}

	entry, err := GlobalKeystore.RetrieveKey(enrollmentID, mspID)
	if err != nil {
		return fmt.Errorf("failed to retrieve key: %w", err)
	}

	// Create MSP directory structure
	mspPath := filepath.Join(outputPath, enrollmentID, "msp")
	dirs := []string{
		filepath.Join(mspPath, "signcerts"),
		filepath.Join(mspPath, "keystore"),
		filepath.Join(mspPath, "cacerts"),
		filepath.Join(mspPath, "tlscacerts"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Write certificate
	certPath := filepath.Join(mspPath, "signcerts", "cert.pem")
	if err := os.WriteFile(certPath, []byte(entry.Certificate), 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key
	keyPath := filepath.Join(mspPath, "keystore", "key.pem")
	if err := os.WriteFile(keyPath, []byte(entry.PrivateKey), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// ValidateCertificate validates that a certificate is properly formatted and not expired
func ValidateCertificate(certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("invalid PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	if cert.NotAfter.Before(time.Now()) {
		return fmt.Errorf("certificate expired on %v", cert.NotAfter)
	}

	return nil
}

// GetKeyForFabricClient retrieves key material for use with Fabric client
func GetKeyForFabricClient(enrollmentID, mspID string) (certPEM []byte, keyPEM []byte, err error) {
	if GlobalKeystore == nil {
		return nil, nil, fmt.Errorf("keystore not initialized")
	}

	entry, err := GlobalKeystore.RetrieveKey(enrollmentID, mspID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve key: %w", err)
	}

	// Validate certificate
	if err := ValidateCertificate(entry.Certificate); err != nil {
		return nil, nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	// Return the certificate and private key as byte arrays (PEM format)
	certPEM = []byte(entry.Certificate)
	keyPEM = []byte(entry.PrivateKey)

	return certPEM, keyPEM, nil
}
