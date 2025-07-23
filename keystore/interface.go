package keystore

import (
	"time"

	"github.com/openbao/openbao/api/v2"
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

// OpenBaoKeystore implements KeystoreManager using OpenBao as the backend
type OpenBaoKeystore struct {
	client     *api.Client
	secretPath string // Base path for storing secrets (e.g., "secret/blockchain-keys")
	userPath   string // Path for user management (e.g., "auth/userpass/users/")
	loginPath  string // Path for login (e.g., "auth/token/login")
}

// OpenBaoConfig contains configuration for OpenBao connection
type OpenBaoConfig struct {
	Address    string `json:"address"`    // OpenBao server address (e.g., "http://localhost:8200")
	Token      string `json:"token"`      // Authentication token
	SecretPath string `json:"secretPath"` // Base path for secrets (e.g., "secret/blockchain-keys")
	UserPath   string `json:"userPath"`   // Path for user management (e.g., "auth/userpass/users/")
	LoginPath  string `json:"loginPath"`  // Path for login (e.g., "auth/token/login")
}
