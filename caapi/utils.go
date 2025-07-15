package caapi

import (
	"blockchain-api/keystore"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric-lib-go/bccsp"
)

func prepareEnrollRequest(req EnrollmentRequest, w http.ResponseWriter, TLSEnroll bool, csrPEM string) ([]byte, error) {
	enrollReq := EnrollmentRequestREST{}
	var err error

	// Set the CSR in the enrollment request
	enrollReq.CertificateRequest = csrPEM

	if TLSEnroll {
		var profile string
		profile = "tls"
		enrollReq.Profile = &profile
	}

	reqBody, err := json.Marshal(enrollReq)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal enrollment request: %v", err)
	}
	return reqBody, nil
}

func parseResponse(EnrollBody []byte, w http.ResponseWriter) (map[string]any, []byte, bool) {
	var enrollResp map[string]any
	var certificatePEM []byte
	var err error

	if err := json.Unmarshal(EnrollBody, &enrollResp); err != nil {
		http.Error(w, "Failed to parse enrollment response: "+err.Error(), http.StatusInternalServerError)
		return nil, nil, true
	}
	// Store the enrolled identity in keystore if enrollment was successful
	if result, ok := enrollResp["result"].(map[string]any); ok {
		certificatePEM, err = base64.StdEncoding.DecodeString(result["Cert"].(string))
		if err != nil {
			http.Error(w, "Failed to decode certificate from enrollment response", http.StatusInternalServerError)
			return nil, nil, true
		}
	}
	return enrollResp, certificatePEM, false
}

func sendEnrollRequest(enrollURL string, reqBody []byte, w http.ResponseWriter, req EnrollmentRequest) ([]byte, bool) {
	httpReq, err := http.NewRequest("POST", enrollURL, bytes.NewBuffer(reqBody))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return nil, true
	}

	// Set Content-Type and Authorization headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(req.EnrollmentID, req.Secret)

	resp, err := CAClient.Do(httpReq)
	if err != nil {
		log.Printf("Failed to enroll identity: %v", err)
		http.Error(w, "Failed to connect to CA server: "+err.Error(), http.StatusInternalServerError)
		return nil, true
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read CA response: "+err.Error(), http.StatusInternalServerError)
		return nil, true
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		http.Error(w, fmt.Sprintf("Enrollment failed: %s", string(body)), resp.StatusCode)
		return nil, true
	}
	return body, false
}

func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// createHTTPClient creates an HTTP client with optional TLS configuration
func createHTTPClient(config CAConfig) *http.Client {
	transport := &http.Transport{}

	// TODO: Add support for custom CA certificates if needed
	if config.SkipTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
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
func createFabricCAAuthToken(clientCsp bccsp.BCCSP, method, urlPath string, body, certificatePEM, privateKeyPEM []byte) (string, error) {
	// Get BCCSP provider
	// Convert PEM to BCCSP key
	bccsKey, err := pemToBCCSPKey(&clientCsp, privateKeyPEM)
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
func getAdminCredentialsFromKeystore(enrollmentID, mspID, userSecret string) ([]byte, []byte, error) {
	// Use the global keystore instance if available
	var entry *keystore.KeystoreEntry
	var err error
	if keystore.GlobalKeystore != nil {

		entry, err = keystore.RetrievePrivateKey(enrollmentID, userSecret)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve admin credentials from global keystore: %v", err)
		}
		return entry.Certificate, entry.PrivateKey, nil
	} else {
		return nil, nil, fmt.Errorf("keystore not initialized")
	}
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

func pemToBCCSPKey(csp *bccsp.BCCSP, privateKeyPEM []byte) (bccsp.Key, error) {
	// Get the default BCCSP provider

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

		bccsKey, err := (*csp).KeyImport(block.Bytes, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: true})
		if err != nil {
			return nil, fmt.Errorf("failed to import ECDSA private key: %v", err)
		}
		return bccsKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", pk)
	}
}
