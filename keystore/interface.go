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
	RetrieveKey(storageKey string) (*KeystoreEntry, error)
	DeleteKey(enrollmentID, mspID, storageKey string) error
	// ListKeys() ([]string, error)
	GetSalt(key string) (string, error)
	StoreSalt(key, salt string) error
	Close() error
	HealthCheck() error
}

// RemoteBadgerKeystore implements KeystoreManager for remote BadgerDB via HTTP API
type RemoteBadgerKeystore struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// GetSalt implements KeystoreManager.
func (r *RemoteBadgerKeystore) GetSalt(key string) (string, error) {
	panic("unimplemented")
}

// StoreSalt implements KeystoreManager.
func (r *RemoteBadgerKeystore) StoreSalt(key string, salt string) error {
	panic("unimplemented")
}

// RemoteBadgerConfig contains configuration for remote BadgerDB connection
type RemoteBadgerConfig struct {
	BaseURL    string `json:"baseUrl"`    // Base URL of the remote BadgerDB API
	APIKey     string `json:"apiKey"`     // API key for authentication
	TimeoutSec int    `json:"timeoutSec"` // HTTP timeout in seconds (default: 30)
}

// GetKeyRequest represents the request payload for remote BadgerDB operations
type GetKeyRequest struct {
	StorageKey string `json:"storageKey"`
}

type StoreKeyRequest struct {
	StorageKey     string `json:"storageKey"`               // Unique key for the stored entry
	EnrollmentID   string `json:"enrollmentId,omitempty"`   // User ID
	MSPID          string `json:"mspId,omitempty"`          // MSP ID
	PrivateKeyPEM  []byte `json:"privateKeyPem"`            // Encrypted private key PEM
	CertificatePEM []byte `json:"certificatePem,omitempty"` // Public certificate PEM
}

type DeleteKeyRequest struct {
	EnrollmentID string `json:"enrollmentId,omitempty"` // User ID
	MSPID        string `json:"mspId,omitempty"`        // MSP ID
	StorageKey   string `json:"storageKey"`             // Unique key for the stored entr
}

// APIResponse represents the response from remote BadgerDB API
type APIResponse struct {
	Success bool           `json:"success"`
	Message string         `json:"message,omitempty"`
	Data    *KeystoreEntry `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
}
