package ca

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// CAConfig contains configuration for connecting to Fabric CA
type CAConfig struct {
	CAURL    string `json:"caUrl"`    // CA server URL
	CAName   string `json:"caName"`   // CA name
	MSPID    string `json:"mspId"`    // MSP ID
	TLSCerts string `json:"tlsCerts"` // Path to TLS certificates (optional)
	SkipTLS  bool   `json:"skipTls"`  // Skip TLS verification for development
}

// EnrollmentRequest represents a request to enroll a new identity
type EnrollmentRequest struct {
	CAConfig     CAConfig `json:"caConfig"`
	EnrollmentID string   `json:"enrollmentId"` // User ID to enroll
	Secret       string   `json:"secret"`       // Enrollment secret
	Profile      string   `json:"profile"`      // Certificate profile (optional)
	CSRInfo      CSRInfo  `json:"csrInfo"`      // Certificate signing request info
}

// CSRInfo contains certificate signing request information
type CSRInfo struct {
	CN    string   `json:"cn"`    // Common Name
	Names []Name   `json:"names"` // Subject names
	Hosts []string `json:"hosts"` // Subject Alternative Names
}

// Name represents a subject name
type Name struct {
	C  string `json:"C"`  // Country
	ST string `json:"ST"` // State
	L  string `json:"L"`  // Locality
	O  string `json:"O"`  // Organization
	OU string `json:"OU"` // Organizational Unit
}

// RegistrationRequest represents a request to register a new identity
type RegistrationRequest struct {
	CAConfig       CAConfig      `json:"caConfig"`
	AdminIdentity  AdminIdentity `json:"adminIdentity"`  // Admin credentials
	RegistrationID string        `json:"registrationId"` // New user ID
	Secret         string        `json:"secret"`         // Optional secret (auto-generated if empty)
	Type           string        `json:"type"`           // Identity type (client, peer, orderer, admin)
	Affiliation    string        `json:"affiliation"`    // User affiliation
	Attributes     []Attribute   `json:"attributes"`     // Additional attributes
}

// Attribute represents a user attribute
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AdminIdentity contains admin credentials for registration operations
type AdminIdentity struct {
	EnrollmentID string `json:"enrollmentId"`
	Secret       string `json:"secret"`
}

// CAInfoResponse represents the response from CA info endpoint
type CAInfoResponse struct {
	Success bool   `json:"success"`
	Result  CAInfo `json:"result"`
}

// CAInfo contains CA server information
type CAInfo struct {
	CAName    string `json:"CAName"`
	CAChain   string `json:"CAChain"`
	IssuerPublicKey string `json:"IssuerPublicKey"`
	IssuerRevocationPublicKey string `json:"IssuerRevocationPublicKey"`
	Version string `json:"Version"`
}

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
	
	if req.Profile != "" {
		enrollReq["profile"] = req.Profile
	}
	
	// Add CSR info if provided
	if req.CSRInfo.CN != "" {
		csr := map[string]interface{}{
			"CN": req.CSRInfo.CN,
		}
		
		if len(req.CSRInfo.Names) > 0 {
			csr["names"] = req.CSRInfo.Names
		}
		
		if len(req.CSRInfo.Hosts) > 0 {
			csr["hosts"] = req.CSRInfo.Hosts
		}
		
		enrollReq["csr"] = csr
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
	
	resp, err := client.Post(enrollURL, "application/json", bytes.NewBuffer(reqBody))
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

	// First, we need to enroll the admin to get authorization token
	adminEnrollReq := map[string]interface{}{
		"id":     req.AdminIdentity.EnrollmentID,
		"secret": req.AdminIdentity.Secret,
	}

	client := createHTTPClient(req.CAConfig)
	
	// Enroll admin
	enrollURL := fmt.Sprintf("%s/api/v1/enroll", req.CAConfig.CAURL)
	if req.CAConfig.CAName != "" {
		enrollURL += "?ca=" + req.CAConfig.CAName
	}
	
	adminReqBody, err := json.Marshal(adminEnrollReq)
	if err != nil {
		http.Error(w, "Failed to marshal admin enrollment request", http.StatusInternalServerError)
		return
	}
	
	adminResp, err := client.Post(enrollURL, "application/json", bytes.NewBuffer(adminReqBody))
	if err != nil {
		log.Printf("Failed to enroll admin: %v", err)
		http.Error(w, "Failed to authenticate admin", http.StatusInternalServerError)
		return
	}
	defer adminResp.Body.Close()

	if adminResp.StatusCode != http.StatusOK {
		http.Error(w, "Admin authentication failed", http.StatusUnauthorized)
		return
	}

	// TODO: Extract certificate and create authorization header
	// For now, we'll return a simplified response
	
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

	// Make registration request (this would need proper authorization header in production)
	registerURL := fmt.Sprintf("%s/api/v1/register", req.CAConfig.CAURL)
	if req.CAConfig.CAName != "" {
		registerURL += "?ca=" + req.CAConfig.CAName
	}
	
	regResp, err := client.Post(registerURL, "application/json", bytes.NewBuffer(regReqBody))
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
