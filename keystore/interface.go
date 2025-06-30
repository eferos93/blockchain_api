package keystore

import "time"

// KeystoreEntry represents a stored private key with metadata
// TODO change private key and certificate to encrypted PEM format
type KeystoreEntry struct {
	EnrollmentID string     `json:"enrollmentId"`
	MSPID        string     `json:"mspId"`
	PrivateKey   string     `json:"privateKey"`  // Encrypted private key PEM
	Certificate  string     `json:"certificate"` // Public certificate PEM
	CreatedAt    time.Time  `json:"createdAt"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
}

// KeystoreManager interface for different storage backends
type KeystoreManager interface {
	StoreKey(enrollmentID, mspID, privateKeyPEM, certificatePEM string) error
	RetrieveKey(enrollmentID, mspID string) (*KeystoreEntry, error)
	DeleteKey(enrollmentID, mspID string) error
	ListKeys() ([]string, error)
	Close() error
	HealthCheck() error
}
