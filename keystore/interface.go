package keystore

import (
	"time"
)

// KeystoreEntry represents a stored private key with metadata
type KeystoreEntry struct {
	EnrollmentID   string     `json:"enrollmentId"`
	PrivateKey     []byte     `json:"privateKey"`
	Certificate    []byte     `json:"certificate"`
	TLSCertificate []byte     `json:"tlsCertificate"`
	CreatedAt      time.Time  `json:"createdAt"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
}

// KeystoreManager interface for different storage backends
type KeystoreManager interface {
	StoreKey(username, password string, privateKeyPEM, certificatePEM, tlsCertificatePEM []byte) error
	RetrieveKey(username, password string) (*KeystoreEntry, error)
	DeleteKey(username, password string) error
	Close() error
	HealthCheck() error
}
