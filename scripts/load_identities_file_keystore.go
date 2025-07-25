package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"blockchain-api/keystore"
)

// IdentityInfo represents an identity to load
type IdentityInfo struct {
	Name         string // e.g., "admin0", "peer0", etc.
	Organization string // e.g., "bsc", "ub"
	Username     string // Combined name, e.g., "bsc-admin0"
	Password     string // Default password for testing
}

// LoadOrganizationIdentities loads all identities for a given organization into the file keystore
func LoadOrganizationIdentities(keystoreBasePath, organization string, fileKeystore keystore.KeystoreManager) error {
	// Define available identities per organization
	var identities []IdentityInfo

	switch organization {
	case "bsc":
		identities = []IdentityInfo{
			{Name: "admin0", Organization: "bsc", Username: "admin0", Password: "admin0pw"},
			{Name: "peer0", Organization: "bsc", Username: "peer0", Password: "peer0pw"},
			{Name: "registrar0", Organization: "bsc", Username: "registrar0", Password: "registrar0pw"},
			{Name: "blockclient", Organization: "bsc", Username: "blockclient", Password: "blockclientpw"},
		}
	case "ub":
		identities = []IdentityInfo{
			{Name: "admin0", Organization: "ub", Username: "admin0", Password: "admin0pw"},
			{Name: "registrar0", Organization: "ub", Username: "registrar0", Password: "registrar0pw"},
		}
	default:
		return fmt.Errorf("unsupported organization: %s", organization)
	}

	fmt.Printf("Loading identities for organization: %s\n", organization)

	// Load each identity
	for _, identity := range identities {
		fmt.Printf("Loading identity: %s\n", identity.Username)

		if err := loadIdentity(fileKeystore, identity); err != nil {
			log.Printf("Failed to load identity %s: %v", identity.Username, err)
			continue
		}

		fmt.Printf("✓ Successfully loaded identity: %s\n", identity.Username)
	}

	fmt.Printf("\nIdentity loading completed for organization: %s\n", organization)

	// Verify loaded identities
	fmt.Printf("\nVerifying loaded identities for %s:\n", organization)
	for _, identity := range identities {
		entry, err := fileKeystore.RetrieveKey(identity.Username, identity.Password)
		if err != nil {
			log.Printf("❌ Failed to verify identity %s: %v", identity.Username, err)
			continue
		}
		fmt.Printf("✓ Verified identity: %s (EnrollmentID: %s)\n", identity.Username, entry.EnrollmentID)
	}

	return nil
}

// LoadAllOrganizationIdentities loads identities for all supported organizations
func LoadAllOrganizationIdentities(keystoreBasePath string, fileKeystore keystore.KeystoreManager) error {
	organizations := []string{"bsc", "ub"}

	for _, org := range organizations {
		if err := LoadOrganizationIdentities(keystoreBasePath, org, fileKeystore); err != nil {
			return fmt.Errorf("failed to load identities for organization %s: %w", org, err)
		}
		fmt.Println()
	}

	return nil
}

func loadIdentity(ks keystore.KeystoreManager, identity IdentityInfo) error {
	// Build paths to identity files
	basePath := filepath.Join("identities", identity.Organization, identity.Name)

	privateKeyPath := filepath.Join(basePath, "msp", "keystore", "key.pem")
	certificatePath := filepath.Join(basePath, "msp", "signcerts", "cert.pem")
	tlsCertificatePath := filepath.Join(basePath, "msp", "tlscacerts", "cert.pem")

	// Read private key
	privateKeyPEM, err := readFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Read certificate
	certificatePEM, err := readFile(certificatePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	// Read TLS certificate
	tlsCertificatePEM, err := readFile(tlsCertificatePath)
	if err != nil {
		return fmt.Errorf("failed to read TLS certificate: %w", err)
	}

	// Store in keystore
	return ks.StoreKey(identity.Username, identity.Password, privateKeyPEM, certificatePEM, tlsCertificatePEM)
}

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	return content, nil
}
