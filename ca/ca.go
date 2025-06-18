package ca

import (
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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"rest-api-go/keystore"
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

// Handler for /fabricCA/info - Get CA information
func InfoHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CAConfig CAConfig `json:"caConfig"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Create HTTP client
	client := createHTTPClient(req.CAConfig)

	// Make request to CA info endpoint
	infoURL := fmt.Sprintf("%s/api/v1/cainfo", req.CAConfig.CAURL)
	if req.CAConfig.CAName != "" {
		infoURL += "?ca=" + req.CAConfig.CAName
	}

	resp, err := client.Get(infoURL)
	if err != nil {
		log.Printf("Failed to get CA info: %v", err)
		http.Error(w, "Failed to connect to CA server", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read CA response", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("CA server error: %s", string(body)), resp.StatusCode)
		return
	}

	var caInfoResp CAInfoResponse
	if err := json.Unmarshal(body, &caInfoResp); err != nil {
		http.Error(w, "Failed to parse CA response", http.StatusInternalServerError)
		return
	}

	// Return success response
	response := map[string]interface{}{
		"success": true,
		"message": "CA info retrieved successfully",
		"caInfo":  caInfoResp.Result,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Handler for /fabricCA/enroll - Enroll a new identity
func EnrollHandler(w http.ResponseWriter, r *http.Request) {
	var req EnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid enrollment request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.EnrollmentID == "" || req.Secret == "" {
		http.Error(w, "enrollmentId and secret are required", http.StatusBadRequest)
		return
	}

	// Create HTTP client
	client := createHTTPClient(req.CAConfig)

	// Prepare enrollment request for CA
	enrollReq := map[string]interface{}{
		"id":     req.EnrollmentID,
		"secret": req.Secret,
	}

	// Add CSR if provided
	if req.CSRInfo.CN != "" {
		csrPEM, privateKey, err := generateCSR(req.CSRInfo)
		if err != nil {
			log.Printf("Failed to generate CSR: %v", err)
			http.Error(w, "Failed to generate CSR", http.StatusInternalServerError)
			return
		}

		// Store the private key for future use
		_ = privateKey

		// Add CSR to enrollment request - Fabric CA expects it in the "csr" field
		enrollReq["csr"] = csrPEM
	}

	if req.Profile != "" {
		enrollReq["profile"] = req.Profile
	}

	reqBody, err := json.Marshal(enrollReq)
	if err != nil {
		http.Error(w, "Failed to marshal request", http.StatusInternalServerError)
		return
	}

	// Make enrollment request to CA
	enrollURL := fmt.Sprintf("%s/api/v1/enroll", req.CAConfig.CAURL)
	if req.CAConfig.CAName != "" {
		enrollURL += "?ca=" + req.CAConfig.CAName
	}

	// Create enrollment request
	httpReq, err := http.NewRequest("POST", enrollURL, bytes.NewBuffer(reqBody))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Set Content-Type and Authorization headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(req.EnrollmentID, req.Secret)

	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("Failed to enroll identity: %v", err)
		http.Error(w, "Failed to connect to CA server", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read CA response", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		http.Error(w, fmt.Sprintf("Enrollment failed: %s", string(body)), resp.StatusCode)
		return
	}

	// Parse enrollment response
	var enrollResp map[string]interface{}
	if err := json.Unmarshal(body, &enrollResp); err != nil {
		http.Error(w, "Failed to parse enrollment response", http.StatusInternalServerError)
		return
	}

	// Store the enrolled identity in keystore if enrollment was successful
	if result, ok := enrollResp["result"].(map[string]interface{}); ok {
		if err := keystore.StoreEnrollmentResult(req.EnrollmentID, req.CAConfig.MSPID, result); err != nil {
			log.Printf("Warning: Failed to store enrollment result in keystore: %v", err)
			// Don't fail the request, just log the warning
		} else {
			log.Printf("Successfully stored enrollment result for %s in keystore", req.EnrollmentID)
		}
	}

	// Return success response
	response := map[string]interface{}{
		"success": true,
		"message": "Identity enrolled successfully",
		"result":  enrollResp,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Handler for /fabricCA/register - Register a new identity
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid registration request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.RegistrationID == "" || req.AdminIdentity.EnrollmentID == "" || req.AdminIdentity.Secret == "" {
		http.Error(w, "registrationId and admin credentials are required", http.StatusBadRequest)
		return
	}

	client := createHTTPClient(req.CAConfig)

	// Prepare registration request
	regReq := map[string]interface{}{
		"id":          req.RegistrationID,
		"type":        req.Type,
		"affiliation": req.Affiliation,
	}

	if req.Secret != "" {
		regReq["secret"] = req.Secret
	}

	if len(req.Attributes) > 0 {
		regReq["attrs"] = req.Attributes
	}

	regReqBody, err := json.Marshal(regReq)
	if err != nil {
		http.Error(w, "Failed to marshal registration request", http.StatusInternalServerError)
		return
	}

	// Make registration request with admin certificate authorization
	registerURL := fmt.Sprintf("%s/api/v1/register", req.CAConfig.CAURL)
	if req.CAConfig.CAName != "" {
		registerURL += "?ca=" + req.CAConfig.CAName
	}

	// Create registration request with admin certificate
	regHttpReq, err := http.NewRequest("POST", registerURL, bytes.NewBuffer(regReqBody))
	if err != nil {
		http.Error(w, "Failed to create registration request", http.StatusInternalServerError)
		return
	}

	regHttpReq.Header.Set("Content-Type", "application/json")

	// Get admin credentials from keystore for proper authorization
	adminCert, adminPrivateKey, err := getAdminCredentialsFromKeystore(req.AdminIdentity.EnrollmentID, req.CAConfig.MSPID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve admin credentials: %v", err), http.StatusInternalServerError)
		return
	}

	// Parse URL to get the path for signing
	parsedURL, err := url.Parse(registerURL)
	if err != nil {
		http.Error(w, "Failed to parse registration URL", http.StatusInternalServerError)
		return
	}

	// Create proper Fabric CA authorization token
	authToken, err := createFabricCAAuthToken("POST", parsedURL.Path, string(regReqBody), adminCert, adminPrivateKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create authorization token: %v", err), http.StatusInternalServerError)
		return
	}

	// Set the authorization header with the proper format
	regHttpReq.Header.Set("Authorization", authToken)

	regResp, err := client.Do(regHttpReq)
	if err != nil {
		log.Printf("Failed to register identity: %v", err)
		http.Error(w, "Failed to connect to CA server", http.StatusInternalServerError)
		return
	}
	defer regResp.Body.Close()

	body, err := io.ReadAll(regResp.Body)
	if err != nil {
		http.Error(w, "Failed to read CA response", http.StatusInternalServerError)
		return
	}

	if regResp.StatusCode != http.StatusOK && regResp.StatusCode != http.StatusCreated {
		http.Error(w, fmt.Sprintf("Registration failed: %s", string(body)), regResp.StatusCode)
		return
	}

	// Parse registration response
	var registerResp map[string]interface{}
	if err := json.Unmarshal(body, &registerResp); err != nil {
		http.Error(w, "Failed to parse registration response", http.StatusInternalServerError)
		return
	}

	// Return success response
	response := map[string]interface{}{
		"success": true,
		"message": "Identity registered successfully",
		"result":  registerResp,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
	} else {
		return "", "", fmt.Errorf("keystore not initialized")
		// Alternatively, you can implement a fallback mechanism to retrieve admin credentials
		// from a different source if the keystore is not available.
	}
}
