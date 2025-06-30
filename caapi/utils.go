package caapi

import (
	"blockchain-api/keystore"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	fabricCAutils "github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
)

// Create HTTP client with optional TLS configuration
func createHTTPClient(config CAConfig) *http.Client {
	transport := &http.Transport{}

	if config.SkipTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// getProjectRoot finds the project root directory by looking for go.mod
func getProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		// Check if go.mod exists in current directory
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root directory
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("go.mod not found")
}

// parsePrivateKey parses a private key from PEM format, handling both PKCS#1 and PKCS#8 formats
func parsePrivateKey(privateKeyPEM string) (any, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Try different private key formats
	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		fmt.Printf("DEBUG: Found PRIVATE KEY block (PKCS#8 format), block length: %d\n", len(block.Bytes))
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %v", err)
		}
		fmt.Printf("DEBUG: Successfully parsed PKCS#8 private key, type: %T\n", key)
		return key, nil

	case "EC PRIVATE KEY":
		// ECDSA private key
		fmt.Printf("DEBUG: Found EC PRIVATE KEY block, block length: %d\n", len(block.Bytes))
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %v", err)
		}
		fmt.Printf("DEBUG: Successfully parsed EC private key, curve: %s\n", key.Curve.Params().Name)
		return key, nil

	case "RSA PRIVATE KEY":
		// RSA private key
		fmt.Printf("DEBUG: Found RSA PRIVATE KEY block, block length: %d\n", len(block.Bytes))
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %v", err)
		}
		fmt.Printf("DEBUG: Successfully parsed RSA private key, bit size: %d\n", key.N.BitLen())
		return key, nil

	default:
		fmt.Printf("DEBUG: Unsupported private key block type: %s\n", block.Type)
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

// parseCertificate parses a certificate from PEM format
func parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

func pemToBCCSPKey(privateKeyPEM []byte) (bccsp.Key, bccsp.BCCSP, error) {
	// Get the default BCCSP provider
	cryptoServiceProvider := factory.GetDefault()

	// Decode the PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the private key based on the block type
	var privateKey any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse PKCS8 private key: %v", err)
		}
	case "EC PRIVATE KEY":
		// EC format
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse EC private key: %v", err)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	// Import the key into BCCSP
	switch pk := privateKey.(type) {
	case *ecdsa.PrivateKey:
		// For ECDSA keys
		bccsKey, err := cryptoServiceProvider.KeyImport(block.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to import ECDSA private key: %v", err)
		}
		return bccsKey, cryptoServiceProvider, nil
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %T", pk)
	}
}

// createFabricCAAuthToken creates the proper authorization token for Fabric CA REST API
// Format: <base64_encoded_certificate>.<base64_encoded_signature>
func createFabricCAAuthToken(method, urlPath string, body, certificatePEM, privateKeyPEM []byte) (string, error) {
	// Get BCCSP provider

	// Convert PEM to BCCSP key
	bccsKey, cryptoServiceProvider, err := pemToBCCSPKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to convert PEM to BCCSP key: %v", err)
	}

	// Use the fabricCAutils.GenECDSAToken function
	token, err := fabricCAutils.GenECDSAToken(cryptoServiceProvider, certificatePEM, bccsKey, method, urlPath, body)
	if err != nil {
		return "", fmt.Errorf("failed to generate ECDSA token: %v", err)
	}

	return token, nil
}

// extractBscRegistrarCredentials extracts certificate and private key of bscRegistrar identity for test purposes
func extractBscRegistrarCredentials() ([]byte, []byte, error) {
	// Get project root
	projectRoot, err := getProjectRoot()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find project root: %v", err)
	}

	bscRegistrarCertPath := filepath.Join(projectRoot, "identities", "bscRegistrar", "msp", "signcerts", "cert.pem")
	bscRegistrarKeyPath := filepath.Join(projectRoot, "identities", "bscRegistrar", "msp", "keystore")

	// Read certificate
	certBytes, err := os.ReadFile(bscRegistrarCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read bscRegistrar certificate: %v", err)
	}

	// Read private key (first file in keystore directory)
	keyFiles, err := os.ReadDir(bscRegistrarKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read bscRegistrar keystore directory: %v", err)
	}

	if len(keyFiles) == 0 {
		return nil, nil, fmt.Errorf("no private key found in bscRegistrar keystore directory")
	}

	keyBytes, err := os.ReadFile(filepath.Join(bscRegistrarKeyPath, keyFiles[0].Name()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read bscRegistrar private key: %v", err)
	}

	// Validate that we can parse both certificate and private key
	cert, err := parseCertificate(string(certBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate certificate: %v", err)
	}

	privateKey, err := parsePrivateKey(string(keyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate private key: %v", err)
	}

	// Ensure the private key matches the certificate's public key
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			if !key.PublicKey.Equal(certPubKey) {
				return nil, nil, fmt.Errorf("private key does not match certificate public key")
			}
		}
	case *rsa.PrivateKey:
		if certPubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if !key.PublicKey.Equal(certPubKey) {
				return nil, nil, fmt.Errorf("private key does not match certificate public key")
			}
		}
	}

	return certBytes, keyBytes, nil
}

// getAdminCredentialsFromKeystore retrieves admin certificate and private key from keystore
func getAdminCredentialsFromKeystore(enrollmentID, mspID string) (string, string, error) {
	// Use the global keystore instance if available
	if keystore.GlobalKeystore != nil {
		entry, err := keystore.GlobalKeystore.RetrieveKey(enrollmentID, mspID)
		if err != nil {
			return "", "", fmt.Errorf("failed to retrieve admin credentials from global keystore: %v", err)
		}
		return entry.Certificate, entry.PrivateKey, nil
	} else {
		return "", "", fmt.Errorf("keystore not initialized")
		// Alternatively, you can implement a fallback mechanism to retrieve admin credentials
		// from a different source if the keystore is not available.
	}
}

// GenerateCSR generates a Certificate Signing Request (CSR) for the given common name and hosts
func GenerateCSR(cn string, hosts []string) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	subject := pkix.Name{
		CommonName: cn,
	}

	// Create the CSR template
	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           hosts,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// Create the CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, priv)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate request: %w", err)
	}

	// PEM encode the CSR
	var csrBuf bytes.Buffer
	if err := pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}); err != nil {
		return "", fmt.Errorf("failed to encode CSR to PEM: %w", err)
	}

	return csrBuf.String(), nil
}

// generateCSR generates a PEM-encoded Certificate Signing Request
func generateCSR(csrInfo CSRInfo) (string, *ecdsa.PrivateKey, error) {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Build the subject name
	subject := pkix.Name{}
	if csrInfo.CN != "" {
		subject.CommonName = csrInfo.CN
	}

	// Add additional names if provided
	for _, name := range csrInfo.Names {
		if name.C != "" {
			subject.Country = append(subject.Country, name.C)
		}
		if name.ST != "" {
			subject.Province = append(subject.Province, name.ST)
		}
		if name.L != "" {
			subject.Locality = append(subject.Locality, name.L)
		}
		if name.O != "" {
			subject.Organization = append(subject.Organization, name.O)
		}
		if name.OU != "" {
			subject.OrganizationalUnit = append(subject.OrganizationalUnit, name.OU)
		}
	}

	// Create the CSR template
	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		DNSNames:           csrInfo.Hosts,
	}

	// Create the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create certificate request: %v", err)
	}

	// Encode to PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return string(csrPEM), privateKey, nil
}
