package keystore

import (
	"net/http"
	"time"
)

// KeystoreEntry represents a stored private key with metadata
type KeystoreEntry struct {
	EnrollmentID string     `json:"enrollmentId"`
	MSPID        string     `json:"mspId"`
	PrivateKey   []byte     `json:"privateKey"`  // Encrypted private key PEM
	Certificate  []byte     `json:"certificate"` // Public certificate PEM
	CreatedAt    time.Time  `json:"createdAt"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
}

// KeystoreManager interface for different storage backends
type KeystoreManager interface {
	StoreKey(enrollmentID, mspID string, privateKeyPEM, certificatePEM []byte) error
	RetrieveKey(enrollmentID, mspID string) (*KeystoreEntry, error)
	DeleteKey(enrollmentID, mspID string) error
	// ListKeys() ([]string, error)
	Close() error
	HealthCheck() error
}

// FileBasedKeystore implements KeystoreManager for test purposes (loads from files, no persistence)
type FileBasedKeystore struct {
	BaseDir string // Directory containing enrollmentID/mspID/cert.pem and key.pem
}

// RemoteBadgerKeystore implements KeystoreManager for remote BadgerDB via HTTP API
type RemoteBadgerKeystore struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// RemoteBadgerConfig contains configuration for remote BadgerDB connection
type RemoteBadgerConfig struct {
	BaseURL    string `json:"baseUrl"`    // Base URL of the remote BadgerDB API
	APIKey     string `json:"apiKey"`     // API key for authentication
	TimeoutSec int    `json:"timeoutSec"` // HTTP timeout in seconds (default: 30)
}

// APIRequest represents the request payload for remote BadgerDB operations
type APIRequest struct {
	EnrollmentID   string `json:"enrollmentId,omitempty"`
	MSPID          string `json:"mspId,omitempty"`
	PrivateKeyPEM  []byte `json:"privateKeyPem,omitempty"`
	CertificatePEM []byte `json:"certificatePem,omitempty"`
}

// APIResponse represents the response from remote BadgerDB API
type APIResponse struct {
	Success bool           `json:"success"`
	Message string         `json:"message,omitempty"`
	Data    *KeystoreEntry `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
}
