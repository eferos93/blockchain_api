package ca

import (
	"blockchain-api/keystore"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
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
func createFabricCAAuthToken(method string, urlPath, body, certificatePEM, privateKeyPEM []byte) (string, error) {
	// Parse the private key
	keyBlock, _ := pem.Decode(privateKeyPEM)
	if keyBlock == nil {
		return "", fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// Create the message to sign: method + urlPath + body + certificate
	message := method + "." + toBase64(urlPath) + "." + toBase64(body) + "." + toBase64(certificatePEM)
	hash := sha256.Sum256([]byte(message))

	signature, err := ecdsaPrivateKeySign(privateKey.(*ecdsa.PrivateKey), hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Create the authorization token
	certB64 := toBase64(certificatePEM)
	sigB64 := toBase64(signature)

	return certB64 + "." + sigB64, nil
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
