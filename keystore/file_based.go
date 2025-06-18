package keystore

import (
	"fmt"
	"os"
	"path/filepath"
)

// FileBasedKeystore implements KeystoreManager for test purposes (loads from files, no persistence)
type FileBasedKeystore struct {
	BaseDir string // Directory containing enrollmentID/mspID/cert.pem and key.pem
}

func NewFileBasedKeystore(baseDir string) *FileBasedKeystore {
	return &FileBasedKeystore{BaseDir: baseDir}
}

func (f *FileBasedKeystore) StoreKey(enrollmentID, mspID, privateKeyPEM, certificatePEM string) error {
	// No-op for file-based keystore
	return nil
}

func (f *FileBasedKeystore) RetrieveKey(enrollmentID, mspID string) (*KeystoreEntry, error) {
	certPath := filepath.Join(f.BaseDir, enrollmentID, "msp", "signcerts", "cert.pem")
	keyPath := filepath.Join(f.BaseDir, enrollmentID, "msp", "keystore", "key.pem")

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	return &KeystoreEntry{
		EnrollmentID: enrollmentID,
		MSPID:        mspID,
		PrivateKey:   string(keyBytes),
		Certificate:  string(certBytes),
	}, nil
}

func (f *FileBasedKeystore) DeleteKey(enrollmentID, mspID string) error {
	// No-op for file-based keystore
	return nil
}

func (f *FileBasedKeystore) ListKeys() ([]string, error) {
	// Not implemented for file-based keystore
	return nil, nil
}

func (f *FileBasedKeystore) Close() error {
	return nil
}

func (f *FileBasedKeystore) HealthCheck() error {
	return nil
}
