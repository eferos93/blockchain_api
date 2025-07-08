package keystore

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
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

// DeriveStorageKey derives a storage key from user secret without exposing it
func DeriveStorageKey(enrollmentID, mspID, userSecret string) (string, error) {
	// Generate or retrieve a salt for this user
	saltKey := fmt.Sprintf("salt:%s:%s", mspID, enrollmentID)

	salt, err := GlobalKeystore.GetSalt(saltKey)
	if err != nil {
		// Generate new salt if doesn't exist
		saltBytes := make([]byte, 32)
		if _, err := rand.Read(saltBytes); err != nil {
			return "", fmt.Errorf("failed to generate salt: %w", err)
		}
		salt = hex.EncodeToString(saltBytes)

		// Store salt for future use
		if err := GlobalKeystore.StoreSalt(saltKey, salt); err != nil {
			return "", fmt.Errorf("failed to store salt: %w", err)
		}
	}

	// Use PBKDF2 to derive a strong key from the user secret
	combined := fmt.Sprintf("%s:%s:%s", enrollmentID, mspID, userSecret)
	saltBytes, _ := hex.DecodeString(salt)
	derivedKey := pbkdf2.Key([]byte(combined), saltBytes, 10000, 32, sha256.New)

	return hex.EncodeToString(derivedKey), nil
}

// StorePrivateKey stores the results from CA enrollment using user secret
func StorePrivateKey(enrollmentID, mspID, userSecret string, cert []byte, privateKey *ecdsa.PrivateKey) error {
	if GlobalKeystore == nil {
		return fmt.Errorf("keystore not initialized")
	}

	// Derive storage key from user secret
	storageKey, err := DeriveStorageKey(enrollmentID, mspID, userSecret)
	if err != nil {
		return fmt.Errorf("failed to derive storage key: %w", err)
	}

	// Convert private key to PEM format
	privateKeyPEM, err := convertPrivateKeyToPEM(privateKey)
	if err != nil {
		return fmt.Errorf("failed to convert private key to PEM: %w", err)
	}

	// Hash certificate for logging/audit purposes
	certHash, err := HashCertificate(cert)
	if err != nil {
		fmt.Printf("Warning: failed to hash certificate: %v\n", err)
	} else {
		fmt.Printf("Storing certificate with hash: %s for user: %s\n", certHash, enrollmentID)
	}

	return GlobalKeystore.StoreKey(storageKey, mspID, cert, privateKeyPEM)
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
func RetrievePrivateKey(enrollmentID, mspID, userSecret string) (*KeystoreEntry, error) {
	if GlobalKeystore == nil {
		return nil, fmt.Errorf("keystore not initialized")
	}

	// Derive the same storage key
	storageKey, err := DeriveStorageKey(enrollmentID, mspID, userSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to derive storage key: %w", err)
	}

	return GlobalKeystore.RetrieveKey(storageKey)
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

	entry, err := RetrievePrivateKey(enrollmentID, mspID, userSecret)
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

// HashCertificate creates a SHA256 hash of the certificate for integrity verification
func HashCertificate(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("invalid PEM certificate")
	}

	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:]), nil
}
