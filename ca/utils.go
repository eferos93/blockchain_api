package ca

import (
	"blockchain-api/keystore"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

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
func parsePrivateKey(privateKeyPEM string) (interface{}, error) {
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

// ExtractBscRegistrarCredentials extracts certificate and private key of bscRegistrar identity for test purposes
func ExtractBscRegistrarCredentials() (string, string, error) {
	// Get project root
	projectRoot, err := getProjectRoot()
	if err != nil {
		return "", "", fmt.Errorf("failed to find project root: %v", err)
	}

	bscRegistrarCertPath := filepath.Join(projectRoot, "identities", "bscRegistrar", "msp", "signcerts", "cert.pem")
	bscRegistrarKeyPath := filepath.Join(projectRoot, "identities", "bscRegistrar", "msp", "keystore")

	// Read certificate
	certBytes, err := os.ReadFile(bscRegistrarCertPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read bscRegistrar certificate: %v", err)
	}

	// Read private key (first file in keystore directory)
	keyFiles, err := os.ReadDir(bscRegistrarKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read bscRegistrar keystore directory: %v", err)
	}

	if len(keyFiles) == 0 {
		return "", "", fmt.Errorf("no private key found in bscRegistrar keystore directory")
	}

	keyBytes, err := os.ReadFile(filepath.Join(bscRegistrarKeyPath, keyFiles[0].Name()))
	if err != nil {
		return "", "", fmt.Errorf("failed to read bscRegistrar private key: %v", err)
	}

	// Validate that we can parse both certificate and private key
	cert, err := parseCertificate(string(certBytes))
	if err != nil {
		return "", "", fmt.Errorf("failed to validate certificate: %v", err)
	}

	privateKey, err := parsePrivateKey(string(keyBytes))
	if err != nil {
		return "", "", fmt.Errorf("failed to validate private key: %v", err)
	}

	// Ensure the private key matches the certificate's public key
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		if certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			if !key.PublicKey.Equal(certPubKey) {
				return "", "", fmt.Errorf("private key does not match certificate public key")
			}
		}
	case *rsa.PrivateKey:
		if certPubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			if !key.PublicKey.Equal(certPubKey) {
				return "", "", fmt.Errorf("private key does not match certificate public key")
			}
		}
	}

	return string(certBytes), string(keyBytes), nil
}

// createFabricCAAuthToken creates the authorization token for Fabric CA requests
func createFabricCAAuthToken(method, uri, body, certPEM, privateKeyPEM string) (string, error) {
	fmt.Printf("DEBUG: Creating auth token for %s %s\n", method, uri)

	// Parse certificate
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %v", err)
	}
	fmt.Printf("DEBUG: Certificate parsed successfully, subject: %s\n", cert.Subject)

	// Parse private key using the robust parser
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// Ensure we have an ECDSA private key (most common in Fabric)
	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key must be ECDSA, got %T", privateKey)
	}

	// Get the PEM-encoded certificate for the token (without headers/footers)
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return "", fmt.Errorf("failed to decode certificate PEM block")
	}

	// The certificate should be base64-encoded DER bytes (from the PEM block)
	certBase64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)
	fmt.Printf("DEBUG: Certificate base64 length: %d\n", len(certBase64))

	// Create the message to sign: method.uri.body.certificate
	message := method + "." + uri + "." + body + "." + certBase64
	fmt.Printf("DEBUG: Message to sign length: %d\n", len(message))

	// Sign the message
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Create signature in DER format
	signature := &struct {
		R, S *big.Int
	}{r, s}

	sigBytes, err := asn1.Marshal(*signature)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %v", err)
	}

	fmt.Printf("DEBUG: Signature bytes length: %d\n", len(sigBytes))

	// Create the authorization token: certificate.signature (both base64 encoded)
	token := certBase64 + "." + base64.StdEncoding.EncodeToString(sigBytes)
	fmt.Printf("DEBUG: Final token length: %d\n", len(token))

	// Debug the token structure
	debugAuthToken(token)

	return token, nil
}

// createFabricCAAuthTokenAlternative - Alternative implementation with PEM-encoded certificate
func createFabricCAAuthTokenAlternative(method, uri, body, certPEM, privateKeyPEM string) (string, error) {
	fmt.Printf("DEBUG: Creating ALTERNATIVE auth token for %s %s\n", method, uri)

	// Parse private key using the robust parser
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// Ensure we have an ECDSA private key (most common in Fabric)
	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key must be ECDSA, got %T", privateKey)
	}

	// Try using PEM-encoded certificate directly (base64 encode the entire PEM block)
	certBase64 := base64.StdEncoding.EncodeToString([]byte(certPEM))
	fmt.Printf("DEBUG: Alternative - PEM certificate base64 length: %d\n", len(certBase64))

	// Create the message to sign: method.uri.body.certificate
	message := method + "." + uri + "." + body + "." + certBase64
	fmt.Printf("DEBUG: Alternative - Message to sign length: %d\n", len(message))

	// Sign the message
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Create signature in DER format
	signature := &struct {
		R, S *big.Int
	}{r, s}

	sigBytes, err := asn1.Marshal(*signature)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %v", err)
	}

	// Create the authorization token: certificate.signature (both base64 encoded)
	token := certBase64 + "." + base64.StdEncoding.EncodeToString(sigBytes)
	fmt.Printf("DEBUG: Alternative - Final token length: %d\n", len(token))

	return token, nil
}

// // createFabricCAAuthToken creates the proper authorization token for Fabric CA REST API
// // Format: <base64_encoded_certificate>.<base64_encoded_signature>
// func createFabricCAAuthToken(method, urlPath, body string, certificate, privateKeyPEM string) (string, error) {
// 	// Parse the certificate
// 	certBlock, _ := pem.Decode([]byte(certificate))
// 	if certBlock == nil {
// 		return "", fmt.Errorf("failed to decode certificate PEM")
// 	}

// 	// Parse the private key
// 	keyBlock, _ := pem.Decode([]byte(privateKeyPEM))
// 	if keyBlock == nil {
// 		return "", fmt.Errorf("failed to decode private key PEM")
// 	}

// 	privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to parse private key: %v", err)
// 	}

// 	// Create the message to sign: method + urlPath + body + certificate
// 	message := method + urlPath + body + base64.StdEncoding.EncodeToString(certBlock.Bytes)

// 	// Create hash of the message
// 	hash := sha256.Sum256([]byte(message))

// 	// Sign the hash
// 	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
// 	if err != nil {
// 		return "", fmt.Errorf("failed to sign message: %v", err)
// 	}

// 	// Encode signature as ASN.1 DER
// 	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
// 	if err != nil {
// 		return "", fmt.Errorf("failed to encode signature: %v", err)
// 	}

// 	// Create the authorization token
// 	certB64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)
// 	sigB64 := base64.StdEncoding.EncodeToString(signature)

// 	return certB64 + "." + sigB64, nil
// }

// createFabricCAAuthTokenV2 - Version 2 following exact Fabric CA client pattern
func createFabricCAAuthTokenV2(method, uri, body, certPEM, privateKeyPEM string) (string, error) {
	fmt.Printf("DEBUG: Creating auth token V2 for %s %s\n", method, uri)

	// Parse certificate
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return "", fmt.Errorf("failed to decode certificate PEM block")
	}

	// Parse private key
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key must be ECDSA, got %T", privateKey)
	}

	// Fabric CA expects: method + uri + body + base64(cert_der_bytes)
	// NO dots between components!
	certBase64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)
	message := method + uri + body + certBase64

	fmt.Printf("DEBUG: V2 Message components:\n")
	fmt.Printf("  Method: %s\n", method)
	fmt.Printf("  URI: %s\n", uri)
	fmt.Printf("  Body: %s\n", body)
	fmt.Printf("  Cert base64: %s...\n", certBase64[:50])
	fmt.Printf("  Full message length: %d\n", len(message))

	// Sign the message
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Create signature in DER format
	signature := &struct {
		R, S *big.Int
	}{r, s}

	sigBytes, err := asn1.Marshal(*signature)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %v", err)
	}

	// Create token: base64(cert_der).base64(signature_der)
	token := certBase64 + "." + base64.StdEncoding.EncodeToString(sigBytes)
	fmt.Printf("DEBUG: V2 Final token length: %d\n", len(token))

	return token, nil
}

// createFabricCAAuthTokenV3 - Version 3 with different message format
func createFabricCAAuthTokenV3(method, uri, body, certPEM, privateKeyPEM string) (string, error) {
	fmt.Printf("DEBUG: Creating auth token V3 for %s %s\n", method, uri)

	// Parse certificate
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return "", fmt.Errorf("failed to decode certificate PEM block")
	}

	// Parse private key
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key must be ECDSA, got %T", privateKey)
	}

	// Try a different message format: just the body + cert
	certBase64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)
	message := body + certBase64

	fmt.Printf("DEBUG: V3 Message length: %d\n", len(message))

	// Sign the message
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Create signature in DER format
	signature := &struct {
		R, S *big.Int
	}{r, s}

	sigBytes, err := asn1.Marshal(*signature)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %v", err)
	}

	// Create token: base64(cert_der).base64(signature_der)
	token := certBase64 + "." + base64.StdEncoding.EncodeToString(sigBytes)
	fmt.Printf("DEBUG: V3 Final token length: %d\n", len(token))

	return token, nil
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

// debugAuthToken decodes and analyzes the authorization token to help debug CA issues
func debugAuthToken(token string) {
	fmt.Printf("DEBUG: Full authorization token: %s\n", token)

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		fmt.Printf("DEBUG: Invalid token format - expected 2 parts, got %d\n", len(parts))
		return
	}

	fmt.Printf("DEBUG: Token has %d parts\n", len(parts))
	fmt.Printf("DEBUG: Certificate part length: %d\n", len(parts[0]))
	fmt.Printf("DEBUG: Signature part length: %d\n", len(parts[1]))

	// Decode certificate part
	certBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("DEBUG: Failed to decode certificate part: %v\n", err)
		return
	}

	fmt.Printf("DEBUG: Decoded certificate bytes length: %d\n", len(certBytes))

	// Try to parse the certificate
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		fmt.Printf("DEBUG: Failed to parse decoded certificate: %v\n", err)
		return
	}

	fmt.Printf("DEBUG: Certificate subject: %s\n", cert.Subject)
	fmt.Printf("DEBUG: Certificate issuer: %s\n", cert.Issuer)
	fmt.Printf("DEBUG: Certificate valid from: %s to %s\n", cert.NotBefore, cert.NotAfter)

	// Show first few bytes of certificate in hex
	if len(certBytes) > 20 {
		fmt.Printf("DEBUG: Certificate first 20 bytes (hex): %x\n", certBytes[:20])
	}
}

// createSimpleFabricCAAuthToken - Simplified version based on Fabric CA client implementation
func createSimpleFabricCAAuthToken(certPEM, privateKeyPEM string) (string, error) {
	fmt.Printf("DEBUG: Creating SIMPLE auth token\n")

	// Parse certificate to get DER bytes
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return "", fmt.Errorf("failed to decode certificate PEM block")
	}

	// Parse private key
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key must be ECDSA, got %T", privateKey)
	}

	// Create a simple message to sign (just the certificate)
	message := base64.StdEncoding.EncodeToString(certBlock.Bytes)

	// Sign the message
	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Create signature in DER format
	signature := &struct {
		R, S *big.Int
	}{r, s}

	sigBytes, err := asn1.Marshal(*signature)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %v", err)
	}

	// Create simple token
	token := message + "." + base64.StdEncoding.EncodeToString(sigBytes)
	fmt.Printf("DEBUG: Simple token length: %d\n", len(token))

	return token, nil
}

// createFabricCAAuthTokenFinal - Final version based on official Fabric CA client
func createFabricCAAuthTokenFinal(method, uri, body, certPEM, privateKeyPEM string) (string, error) {
	fmt.Printf("DEBUG: Creating FINAL auth token for %s %s\n", method, uri)

	// Parse certificate
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return "", fmt.Errorf("failed to decode certificate PEM block")
	}

	// Parse private key
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key must be ECDSA, got %T", privateKey)
	}

	// The message to sign is: method + "." + uri + "." + body + "." + base64(cert)
	// This is the exact format used by the official Fabric CA client
	certBase64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)
	msgToSign := fmt.Sprintf("%s.%s.%s.%s", method, uri, body, certBase64)

	fmt.Printf("DEBUG: FINAL Message to sign: %s...\n", msgToSign[:100])
	fmt.Printf("DEBUG: FINAL Message length: %d\n", len(msgToSign))

	// Sign the message using SHA256
	hash := sha256.Sum256([]byte(msgToSign))
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Encode signature as DER
	sigStruct := struct {
		R, S *big.Int
	}{r, s}

	derSig, err := asn1.Marshal(sigStruct)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %v", err)
	}

	// Create the final token: cert.signature (both base64 encoded)
	token := certBase64 + "." + base64.StdEncoding.EncodeToString(derSig)

	fmt.Printf("DEBUG: FINAL Token cert part length: %d\n", len(certBase64))
	fmt.Printf("DEBUG: FINAL Token sig part length: %d\n", len(base64.StdEncoding.EncodeToString(derSig)))
	fmt.Printf("DEBUG: FINAL Token total length: %d\n", len(token))

	return token, nil
}

// createFabricCAAuthTokenCorrect - Correct version following exact Fabric CA specification
func createFabricCAAuthTokenCorrect(method, uri, body, certPEM, privateKeyPEM string) (string, error) {
	fmt.Printf("DEBUG: Creating CORRECT auth token for %s %s\n", method, uri)

	// Parse certificate
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return "", fmt.Errorf("failed to decode certificate PEM block")
	}

	// Parse private key
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key must be ECDSA, got %T", privateKey)
	}

	// Based on Fabric CA client source: message is method + uri + body + base64(cert)
	// NO dots between components - they are concatenated directly
	certBase64 := base64.StdEncoding.EncodeToString(certBlock.Bytes)
	msgToSign := method + uri + body + certBase64

	fmt.Printf("DEBUG: CORRECT Message to sign (first 200 chars): %s...\n", msgToSign[:min(200, len(msgToSign))])
	fmt.Printf("DEBUG: CORRECT Message components:\n")
	fmt.Printf("  Method: '%s'\n", method)
	fmt.Printf("  URI: '%s'\n", uri)
	fmt.Printf("  Body: '%s'\n", body[:min(100, len(body))])
	fmt.Printf("  Cert base64: '%s...'\n", certBase64[:50])
	fmt.Printf("  Total length: %d\n", len(msgToSign))

	// Sign the message using SHA256
	hash := sha256.Sum256([]byte(msgToSign))
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	// Encode signature as DER
	sigStruct := struct {
		R, S *big.Int
	}{r, s}

	derSig, err := asn1.Marshal(sigStruct)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %v", err)
	}

	// Create the final token: cert.signature (both base64 encoded)
	token := certBase64 + "." + base64.StdEncoding.EncodeToString(derSig)

	fmt.Printf("DEBUG: CORRECT Token total length: %d\n", len(token))

	return token, nil
}

// AnalyzeBscRegistrarCert analyzes the bscRegistrar certificate file to understand its format
func AnalyzeBscRegistrarCert() {
	fmt.Printf("=== ANALYZING BSC REGISTRAR CERTIFICATE ===\n")

	cert, key, err := ExtractBscRegistrarCredentials()
	if err != nil {
		fmt.Printf("Error extracting credentials: %v\n", err)
		return
	}

	fmt.Printf("Certificate length: %d bytes\n", len(cert))
	fmt.Printf("Private key length: %d bytes\n", len(key))

	fmt.Printf("\nCertificate (first 200 chars):\n%s\n", cert[:min(200, len(cert))])
	fmt.Printf("\nPrivate key (first 200 chars):\n%s\n", key[:min(200, len(key))])

	// Parse certificate
	certBlock, _ := pem.Decode([]byte(cert))
	if certBlock != nil {
		fmt.Printf("\nCertificate PEM block type: %s\n", certBlock.Type)
		fmt.Printf("Certificate DER bytes length: %d\n", len(certBlock.Bytes))

		parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			fmt.Printf("Failed to parse certificate: %v\n", err)
		} else {
			fmt.Printf("Certificate subject: %s\n", parsedCert.Subject)
			fmt.Printf("Certificate issuer: %s\n", parsedCert.Issuer)
			fmt.Printf("Certificate serial: %s\n", parsedCert.SerialNumber)
			fmt.Printf("Certificate public key type: %T\n", parsedCert.PublicKey)
		}
	}

	// Parse private key
	keyBlock, _ := pem.Decode([]byte(key))
	if keyBlock != nil {
		fmt.Printf("\nPrivate key PEM block type: %s\n", keyBlock.Type)
		fmt.Printf("Private key bytes length: %d\n", len(keyBlock.Bytes))
	}

	fmt.Printf("=== END ANALYSIS ===\n")
}

// TestDifferentAuthTokenFormats tests different authorization token formats
func TestDifferentAuthTokenFormats() {
	fmt.Printf("=== TESTING DIFFERENT AUTH TOKEN FORMATS ===\n")

	// First analyze the certificate
	AnalyzeBscRegistrarCert()

	cert, key, err := ExtractBscRegistrarCredentials()
	if err != nil {
		fmt.Printf("Error extracting credentials: %v\n", err)
		return
	}

	method := "POST"
	uri := "/api/v1/register"
	body := `{"id":"testuser","secret":"testpass"}`

	fmt.Printf("\n1. Testing original format (DER-encoded cert):\n")
	token1, err := createFabricCAAuthToken(method, uri, body, cert, key)
	if err != nil {
		fmt.Printf("Error creating token 1: %v\n", err)
	} else {
		fmt.Printf("Token 1 created successfully, length: %d\n", len(token1))
	}

	fmt.Printf("\n2. Testing alternative format (PEM-encoded cert):\n")
	token2, err := createFabricCAAuthTokenAlternative(method, uri, body, cert, key)
	if err != nil {
		fmt.Printf("Error creating token 2: %v\n", err)
	} else {
		fmt.Printf("Token 2 created successfully, length: %d\n", len(token2))
	}

	fmt.Printf("\n3. Testing simple format:\n")
	token3, err := createSimpleFabricCAAuthToken(cert, key)
	if err != nil {
		fmt.Printf("Error creating token 3: %v\n", err)
	} else {
		fmt.Printf("Token 3 created successfully, length: %d\n", len(token3))
	}

	fmt.Printf("\n4. Testing Fabric CA Auth Token V2:\n")
	tokenV2, err := createFabricCAAuthTokenV2(method, uri, body, cert, key)
	if err != nil {
		fmt.Printf("Error creating token V2: %v\n", err)
	} else {
		fmt.Printf("Token V2 created successfully, length: %d\n", len(tokenV2))
	}

	fmt.Printf("\n5. Testing Fabric CA Auth Token V3:\n")
	tokenV3, err := createFabricCAAuthTokenV3(method, uri, body, cert, key)
	if err != nil {
		fmt.Printf("Error creating token V3: %v\n", err)
	} else {
		fmt.Printf("Token V3 created successfully, length: %d\n", len(tokenV3))
	}

	fmt.Printf("\n6. Testing Fabric CA Auth Token FINAL:\n")
	tokenFinal, err := createFabricCAAuthTokenFinal(method, uri, body, cert, key)
	if err != nil {
		fmt.Printf("Error creating final token: %v\n", err)
	} else {
		fmt.Printf("Final token created successfully, length: %d\n", len(tokenFinal))
	}

	fmt.Printf("\n7. Testing Fabric CA Auth Token CORRECT:\n")
	tokenCorrect, err := createFabricCAAuthTokenCorrect(method, uri, body, cert, key)
	if err != nil {
		fmt.Printf("Error creating correct token: %v\n", err)
	} else {
		fmt.Printf("Correct token created successfully, length: %d\n", len(tokenCorrect))
	}

	fmt.Printf("=== END TOKEN FORMAT TESTING ===\n")
}

// tryBasicAuthForRegister tries basic authentication for admin during registration
