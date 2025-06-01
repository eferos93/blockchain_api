package keystore

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// BadgerKeystore uses BadgerDB for fast, lightweight encrypted key-value storage
type BadgerKeystore struct {
	db        *badger.DB
	encryptor *EncryptedKeystore // Reuse encryption logic
}

// NewBadgerKeystore creates a new BadgerDB-backed keystore
func NewBadgerKeystore(dbPath string, masterPassword string) (*BadgerKeystore, error) {
	// Configure BadgerDB options
	opts := badger.DefaultOptions(dbPath)
	opts.Logger = nil      // Disable logging for cleaner output
	opts.SyncWrites = true // Ensure durability

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open BadgerDB: %w", err)
	}

	// Initialize encryptor for key encryption
	encryptor := NewEncryptedKeystore("/tmp", masterPassword)

	return &BadgerKeystore{
		db:        db,
		encryptor: encryptor,
	}, nil
}

// StoreKey stores an encrypted private key in BadgerDB
func (b *BadgerKeystore) StoreKey(enrollmentID, mspID, privateKeyPEM, certificatePEM string) error {
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
	encryptedData, err := b.encryptor.encrypt(entryData)
	if err != nil {
		return fmt.Errorf("failed to encrypt keystore entry: %w", err)
	}

	// Generate key
	key := fmt.Sprintf("%s:%s", enrollmentID, mspID)

	// Store in BadgerDB
	err = b.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), encryptedData)
	})

	if err != nil {
		return fmt.Errorf("failed to store key in BadgerDB: %w", err)
	}

	return nil
}

// RetrieveKey retrieves and decrypts a private key from BadgerDB
func (b *BadgerKeystore) RetrieveKey(enrollmentID, mspID string) (*KeystoreEntry, error) {
	key := fmt.Sprintf("%s:%s", enrollmentID, mspID)

	var encryptedData []byte
	err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}

		encryptedData, err = item.ValueCopy(nil)
		return err
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, fmt.Errorf("key not found for %s:%s", enrollmentID, mspID)
		}
		return nil, fmt.Errorf("failed to retrieve key: %w", err)
	}

	// Decrypt the data
	entryData, err := b.encryptor.decrypt(encryptedData)
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

// DeleteKey removes a key from BadgerDB
func (b *BadgerKeystore) DeleteKey(enrollmentID, mspID string) error {
	key := fmt.Sprintf("%s:%s", enrollmentID, mspID)

	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// ListKeys returns all stored key identifiers
func (b *BadgerKeystore) ListKeys() ([]string, error) {
	var keys []string

	err := b.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // Only need keys
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := string(item.Key())
			keys = append(keys, key)
		}
		return nil
	})

	return keys, err
}

// Close closes the BadgerDB connection
func (b *BadgerKeystore) Close() error {
	return b.db.Close()
}

// GarbageCollect runs BadgerDB garbage collection to reclaim space
func (b *BadgerKeystore) GarbageCollect() error {
	return b.db.RunValueLogGC(0.5)
}
