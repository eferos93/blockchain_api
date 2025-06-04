package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// KeystoreEntry represents a stored private key with metadata
type KeystoreEntry struct {
	EnrollmentID string     `json:"enrollmentId"`
	MSPID        string     `json:"mspId"`
	PrivateKey   string     `json:"privateKey"`  // Encrypted private key PEM
	Certificate  string     `json:"certificate"` // Public certificate PEM
	CreatedAt    time.Time  `json:"createdAt"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
}

// EncryptedKeystore manages encrypted private key storage
type EncryptedKeystore struct {
	storePath string
	masterKey []byte
}

// NewEncryptedKeystore creates a new encrypted keystore
func NewEncryptedKeystore(storePath string, masterPassword string) *EncryptedKeystore {
	// Derive a master key from password using PBKDF2
	salt := []byte("fabric-api-keystore-salt") // In production, use random salt per keystore
	masterKey := pbkdf2.Key([]byte(masterPassword), salt, 10000, 32, sha256.New)

	// Ensure store directory exists
	os.MkdirAll(storePath, 0700)

	return &EncryptedKeystore{
		storePath: storePath,
		masterKey: masterKey,
	}
}

// encrypt encrypts data using AES-GCM
func (k *EncryptedKeystore) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES-GCM
func (k *EncryptedKeystore) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// StoreKey stores a private key and certificate securely
func (k *EncryptedKeystore) StoreKey(enrollmentID, mspID, privateKeyPEM, certificatePEM string) error {
	entry := KeystoreEntry{
		EnrollmentID: enrollmentID,
		MSPID:        mspID,
		PrivateKey:   privateKeyPEM,
		Certificate:  certificatePEM,
		CreatedAt:    time.Now(),
	}

	// Serialize entry
	entryData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal keystore entry: %w", err)
	}

	// Encrypt entry
	encryptedData, err := k.encrypt(entryData)
	if err != nil {
		return fmt.Errorf("failed to encrypt keystore entry: %w", err)
	}

	// Generate filename
	keyID := k.generateKeyID(enrollmentID, mspID)
	filePath := filepath.Join(k.storePath, keyID+".key")

	// Write to file with restrictive permissions
	return os.WriteFile(filePath, encryptedData, 0600)
}

// RetrieveKey retrieves a private key and certificate
func (k *EncryptedKeystore) RetrieveKey(enrollmentID, mspID string) (*KeystoreEntry, error) {
	keyID := k.generateKeyID(enrollmentID, mspID)
	filePath := filepath.Join(k.storePath, keyID+".key")

	// Read encrypted file
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore entry: %w", err)
	}

	// Decrypt data
	entryData, err := k.decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt keystore entry: %w", err)
	}

	// Deserialize entry
	var entry KeystoreEntry
	if err := json.Unmarshal(entryData, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keystore entry: %w", err)
	}

	return &entry, nil
}

// DeleteKey removes a stored key
func (k *EncryptedKeystore) DeleteKey(enrollmentID, mspID string) error {
	keyID := k.generateKeyID(enrollmentID, mspID)
	filePath := filepath.Join(k.storePath, keyID+".key")
	return os.Remove(filePath)
}

// ListKeys returns all stored key identifiers
func (k *EncryptedKeystore) ListKeys() ([]string, error) {
	files, err := os.ReadDir(k.storePath)
	if err != nil {
		return nil, err
	}

	var keyIDs []string
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".key" {
			keyID := file.Name()[:len(file.Name())-4] // Remove .key extension
			keyIDs = append(keyIDs, keyID)
		}
	}

	return keyIDs, nil
}

// generateKeyID creates a unique identifier for a key
func (k *EncryptedKeystore) generateKeyID(enrollmentID, mspID string) string {
	input := fmt.Sprintf("%s:%s", enrollmentID, mspID)
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes for shorter ID
}
