package keystore

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// GlobalKeystore is the application-wide keystore instance
var GlobalKeystore KeystoreManager

// InitializeKeystore initializes the global keystore
func InitializeKeystore(keystoreType, config, masterPassword string) error {
	switch keystoreType {
	case "openbao":
		// OpenBao keystore
		var openbaoConfig OpenBaoConfig
		if err := json.Unmarshal([]byte(config), &openbaoConfig); err != nil {
			return fmt.Errorf("failed to parse OpenBao config: %w", err)
		}

		openbaoClient, err := NewOpenBaoKeystore(openbaoConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize OpenBao keystore: %w", err)
		}

		// Test connection
		if err := openbaoClient.HealthCheck(); err != nil {
			return fmt.Errorf("OpenBao health check failed: %w", err)
		}

		GlobalKeystore = openbaoClient
	default:
		return fmt.Errorf("unsupported keystore type: %s (supported: openbao, remote_badger)", keystoreType)
	}
	return nil
}

// StorePrivateKey stores the results from CA enrollment using user secret
func StorePrivateKey(enrollmentID, userSecret string, cert, tlsCert []byte, privateKey *ecdsa.PrivateKey) error {
	if GlobalKeystore == nil {
		return fmt.Errorf("keystore not initialized")
	}

	// Convert private key to PEM format
	privateKeyPEM, err := convertPrivateKeyToPEM(privateKey)
	if err != nil {
		return fmt.Errorf("failed to convert private key to PEM: %w", err)
	}
	return GlobalKeystore.StoreKey(enrollmentID, userSecret, cert, privateKeyPEM, tlsCert)
}

// convertPrivateKeyToPEM converts an ECDSA private key to PEM format
func convertPrivateKeyToPEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}

// RetrievePrivateKey retrieves private key using user secret
func RetrievePrivateKey(enrollmentID, userSecret string) (*KeystoreEntry, error) {
	if GlobalKeystore == nil {
		return nil, fmt.Errorf("keystore not initialized")
	}

	return GlobalKeystore.RetrieveKey(enrollmentID, userSecret)
}

// ValidateCertificate validates that a certificate is properly formatted and not expired
func ValidateCertificate(certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
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
func GetKeyForFabricClient(enrollmentID, mspID, userSecret string) (certPEM []byte, keyPEM []byte, err error) {
	if GlobalKeystore == nil {
		return nil, nil, fmt.Errorf("keystore not initialized")
	}

	entry, err := RetrievePrivateKey(enrollmentID, userSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve key: %w", err)
	}

	// Validate certificate
	if err := ValidateCertificate([]byte(entry.Certificate)); err != nil {
		return nil, nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	// Return the certificate and private key as byte arrays (PEM format)
	certPEM = []byte(entry.Certificate)
	keyPEM = []byte(entry.PrivateKey)

	return certPEM, keyPEM, nil
}
