package caapi

import (
	"blockchain-api/keystore"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-ca/lib"
	"github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
)

// createFabricCAClient creates a new Fabric CA client with the given configuration
func createFabricCAClient(config CAConfig) (*lib.Client, error) {
	// Create client configuration
	clientConfig := &lib.ClientConfig{
		URL:    config.CAURL,
		CAName: config.CAName,
		MSPDir: "", // We'll handle credentials separately
	}

	// Configure TLS if needed
	if config.SkipTLS {
		clientConfig.TLS = tls.ClientTLSConfig{
			Enabled: false,
		}
	}

	// Create the client
	client := &lib.Client{
		Config: clientConfig,
	}

	// Initialize the client
	err := client.Init()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CA client: %v", err)
	}

	return client, nil
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

func ecdsaPrivateKeySign(privateKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	n := privateKey.Params().Params().N

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, err
	}

	s = canonicalECDSASignatureSValue(s, n)

	return asn1ECDSASignature(r, s)
}

func canonicalECDSASignatureSValue(s *big.Int, curveN *big.Int) *big.Int {
	halfOrder := new(big.Int).Rsh(curveN, 1)
	if s.Cmp(halfOrder) <= 0 {
		return s
	}

	// Set s to N - s so it is in the lower part of signature space, less or equal to half order
	return new(big.Int).Sub(curveN, s)
}

type ecdsaSignature struct {
	R, S *big.Int
}

func asn1ECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{
		R: r,
		S: s,
	})
}

func toBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// createFabricCAAuthToken creates the proper authorization token for Fabric CA REST API
// Format: <base64_encoded_certificate>.<base64_encoded_signature>
func createFabricCAAuthToken(clientCsp bccsp.BCCSP, method, urlPath string, body, certificatePEM, privateKeyPEM []byte) (string, error) {
	// Get BCCSP provider

	// Convert PEM to BCCSP key
	bccsKey, err := pemToBCCSPKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to convert PEM to BCCSP key: %v", err)
	}

	// Use the util.GenECDSAToken function
	token, err := util.GenECDSAToken(clientCsp, certificatePEM, bccsKey, method, urlPath, body)
	if err != nil {
		return "", fmt.Errorf("failed to generate ECDSA token: %v", err)
	}

	return token, nil
}

// getAdminCredentialsFromKeystore retrieves admin certificate and private key from keystore
func getAdminCredentialsFromKeystore(enrollmentID, mspID string) ([]byte, []byte, error) {
	// Use the global keystore instance if available
	if keystore.GlobalKeystore != nil {
		entry, err := keystore.GlobalKeystore.RetrieveKey(enrollmentID, mspID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve admin credentials from global keystore: %v", err)
		}
		return entry.Certificate, entry.PrivateKey, nil
	}

	// Fallback to local BadgerDB keystore for backward compatibility
	keystoreInstance, err := keystore.NewBadgerKeystore("./badger-keystore", "defaultPassword")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize BadgerDB keystore: %v", err)
	}
	defer keystoreInstance.Close()

	// Retrieve the admin credentials
	entry, err := keystoreInstance.RetrieveKey(enrollmentID, mspID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve admin credentials from keystore: %v", err)
	}

	return entry.Certificate, entry.PrivateKey, nil
}

func loadAdminCredentialsForTest() ([]byte, []byte, error) {
	// For testing purposes, we can hardcode the admin credentials
	// In production, this should be retrieved from a secure keystore
	basePath := filepath.Join("..", "identities", "bscRegistrar", "msp")
	certPath := filepath.Join(basePath, "signcerts", "cert.pem")
	keyPath := filepath.Join(basePath, "keystore", "key.pem")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read admin certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read admin private key: %w", err)
	}
	return certPEM, keyPEM, nil
}

func pemToBCCSPKey(privateKeyPEM []byte) (bccsp.Key, error) {
	// Get the default BCCSP provider
	csp := factory.GetDefault()

	// Decode the PEM block
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the private key based on the block type
	var privateKey any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %v", err)
		}
	case "EC PRIVATE KEY":
		// EC format
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	// Import the key into BCCSP
	switch pk := privateKey.(type) {
	case *ecdsa.PrivateKey:
		// For ECDSA keys
		bccsKey, err := csp.KeyImport(pk, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
		if err != nil {
			return nil, fmt.Errorf("failed to import ECDSA private key: %v", err)
		}
		return bccsKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", pk)
	}
}
