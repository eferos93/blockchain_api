package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// FileKeystore implements KeystoreManager using file-based encrypted storage
type FileKeystore struct {
	basePath string // Base directory for storing encrypted user data
	salt     []byte // Salt for key derivation (stored in keystore config)
}

// FileKeystoreConfig contains configuration for file-based keystore
type FileKeystoreConfig struct {
	BasePath string `json:"basePath"` // Base directory for keystore data
	Salt     string `json:"salt"`     // Base64 encoded salt for key derivation
}

// EncryptedKeystoreEntry represents an encrypted keystore entry stored to disk
type EncryptedKeystoreEntry struct {
	EnrollmentID      string    `json:"enrollmentId"`
	EncryptedData     []byte    `json:"encryptedData"` // AES-encrypted JSON of KeystoreEntry
	Nonce             []byte    `json:"nonce"`         // AES-GCM nonce
	CreatedAt         time.Time `json:"createdAt"`
	KeyDerivationSalt []byte    `json:"keyDerivationSalt"` // Per-user salt for key derivation
}

const (
	// Cryptographic constants
	aesKeySize   = 32     // AES-256
	nonceSize    = 12     // GCM nonce size
	saltSize     = 32     // Salt size for PBKDF2
	pbkdf2Rounds = 100000 // PBKDF2 iteration count

	// File organization
	keystoreFileName  = "keystore.json"
	userDirPermission = 0700 // Only owner can read/write/execute
	filePermission    = 0600 // Only owner can read/write
)

// NewFileKeystore creates a new file-based keystore
func NewFileKeystore(config FileKeystoreConfig) (*FileKeystore, error) {
	if config.BasePath == "" {
		return nil, fmt.Errorf("basePath is required")
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(config.BasePath, userDirPermission); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	// Initialize or load salt
	var salt []byte
	if config.Salt != "" {
		// TODO: Decode base64 salt from config
		salt = []byte(config.Salt) // Simplified for now
	} else {
		// Generate new salt
		salt = make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	return &FileKeystore{
		basePath: config.BasePath,
		salt:     salt,
	}, nil
}

// StoreKey stores an encrypted private key in the file system
func (f *FileKeystore) StoreKey(username, password string, privateKeyPEM, certificatePEM, tlsCertificatePEM []byte) error {
	// Create user directory
	userDir := filepath.Join(f.basePath, username)
	if err := os.MkdirAll(userDir, userDirPermission); err != nil {
		return fmt.Errorf("failed to create user directory: %w", err)
	}

	// Generate per-user salt for additional security
	userSalt := make([]byte, saltSize)
	if _, err := rand.Read(userSalt); err != nil {
		return fmt.Errorf("failed to generate user salt: %w", err)
	}

	// Derive encryption key from user password
	encryptionKey := f.deriveKey(password, userSalt)

	// Create keystore entry
	entry := &KeystoreEntry{
		EnrollmentID:   username,
		PrivateKey:     privateKeyPEM,
		Certificate:    certificatePEM,
		TLSCertificate: tlsCertificatePEM,
		CreatedAt:      time.Now(),
	}

	// Serialize entry to JSON
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal keystore entry: %w", err)
	}

	// Encrypt the entry data
	encryptedData, nonce, err := f.encrypt(entryJSON, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt keystore entry: %w", err)
	}

	// Create encrypted entry for storage
	encryptedEntry := &EncryptedKeystoreEntry{
		EnrollmentID:      username,
		EncryptedData:     encryptedData,
		Nonce:             nonce,
		CreatedAt:         time.Now(),
		KeyDerivationSalt: userSalt,
	}

	// Save to file
	keystoreFile := filepath.Join(userDir, keystoreFileName)
	return f.saveEncryptedEntry(keystoreFile, encryptedEntry)
}

// RetrieveKey retrieves and decrypts a private key from the file system
func (f *FileKeystore) RetrieveKey(username, password string) (*KeystoreEntry, error) {
	// Load encrypted entry from file
	keystoreFile := filepath.Join(f.basePath, username, keystoreFileName)
	encryptedEntry, err := f.loadEncryptedEntry(keystoreFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load encrypted entry: %w", err)
	}

	// Derive encryption key using stored salt
	encryptionKey := f.deriveKey(password, encryptedEntry.KeyDerivationSalt)

	// Decrypt the entry data
	decryptedData, err := f.decrypt(encryptedEntry.EncryptedData, encryptedEntry.Nonce, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keystore entry (wrong password?): %w", err)
	}

	// Deserialize entry from JSON
	var entry KeystoreEntry
	if err := json.Unmarshal(decryptedData, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keystore entry: %w", err)
	}

	return &entry, nil
}

// DeleteKey removes a user's keystore entry from the file system
func (f *FileKeystore) DeleteKey(username, password string) error {
	// Verify password by attempting to retrieve key first
	_, err := f.RetrieveKey(username, password)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Remove user directory and all contents
	userDir := filepath.Join(f.basePath, username)
	if err := os.RemoveAll(userDir); err != nil {
		return fmt.Errorf("failed to remove user directory: %w", err)
	}

	return nil
}

// Close performs cleanup (no-op for file keystore)
func (f *FileKeystore) Close() error {
	// File keystore doesn't need explicit cleanup
	return nil
}

// HealthCheck verifies that the keystore is accessible
func (f *FileKeystore) HealthCheck() error {
	// Check if base directory exists and is writable
	if _, err := os.Stat(f.basePath); os.IsNotExist(err) {
		return fmt.Errorf("keystore base directory does not exist: %s", f.basePath)
	}

	// Test write permissions by creating a temporary file
	testFile := filepath.Join(f.basePath, ".health_check")
	if err := os.WriteFile(testFile, []byte("test"), filePermission); err != nil {
		return fmt.Errorf("keystore directory is not writable: %w", err)
	}

	// Clean up test file
	os.Remove(testFile)
	return nil
}

// deriveKey derives an encryption key from password and salt using PBKDF2
func (f *FileKeystore) deriveKey(password string, userSalt []byte) []byte {
	// Combine global salt with user-specific salt for additional security
	combinedSalt := append(f.salt, userSalt...)
	return pbkdf2.Key([]byte(password), combinedSalt, pbkdf2Rounds, aesKeySize, sha256.New)
}

// encrypt encrypts data using AES-GCM
func (f *FileKeystore) encrypt(data, key []byte) (encrypted, nonce []byte, err error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	encrypted = gcm.Seal(nil, nonce, data, nil)
	return encrypted, nonce, nil
}

// decrypt decrypts data using AES-GCM
func (f *FileKeystore) decrypt(encrypted, nonce, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt data
	decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return decrypted, nil
}

// saveEncryptedEntry saves an encrypted entry to a file
func (f *FileKeystore) saveEncryptedEntry(filename string, entry *EncryptedKeystoreEntry) error {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted entry: %w", err)
	}

	if err := os.WriteFile(filename, data, filePermission); err != nil {
		return fmt.Errorf("failed to write keystore file: %w", err)
	}

	return nil
}

// loadEncryptedEntry loads an encrypted entry from a file
func (f *FileKeystore) loadEncryptedEntry(filename string) (*EncryptedKeystoreEntry, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore file: %w", err)
	}

	var entry EncryptedKeystoreEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted entry: %w", err)
	}

	return &entry, nil
}
