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

// createFabricCAAuthToken creates the proper authorization token for Fabric CA REST API
// Format: <base64_encoded_certificate>.<base64_encoded_signature>
func createFabricCAAuthToken(method, urlPath, body string, certificate, privateKeyPEM string) (string, error) {
	// Parse the certificate
	certBlock, _ := pem.Decode([]byte(certificate))
	if certBlock == nil {
		return "", fmt.Errorf("failed to decode certificate PEM")
	}

	// Parse the private key
	keyBlock, _ := pem.Decode([]byte(privateKeyPEM))
	if keyBlock == nil {
		return "", fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// Create the message to sign: method + urlPath + body + certificate
	message := method + urlPath + body + base64.StdEncoding.EncodeToString(certBlock.Bytes)

	// Create hash of the message
	hash := sha256.Sum256([]byte(message))

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Encode signature as ASN.1 DER
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return "", fmt.Errorf("failed to encode signature: %v", err)
	}

	// Create the authorization token
	certB64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)
	sigB64 := base64.StdEncoding.EncodeToString(signature)

	return certB64 + "." + sigB64, nil
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
	}

	// Fallback to local BadgerDB keystore for backward compatibility
	keystoreInstance, err := keystore.NewBadgerKeystore("./badger-keystore", "defaultPassword")
	if err != nil {
		return "", "", fmt.Errorf("failed to initialize BadgerDB keystore: %v", err)
	}
	defer keystoreInstance.Close()

	// Retrieve the admin credentials
	entry, err := keystoreInstance.RetrieveKey(enrollmentID, mspID)
	if err != nil {
		return "", "", fmt.Errorf("failed to retrieve admin credentials from keystore: %v", err)
	}

	return entry.Certificate, entry.PrivateKey, nil
}
