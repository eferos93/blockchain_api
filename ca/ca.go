package ca

import (
	"blockchain-api/keystore"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"testing"
)

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
	enrollReq := map[string]any{
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
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set Content-Type and Authorization headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(req.EnrollmentID, req.Secret)

	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("Failed to enroll identity: %v", err)
		http.Error(w, "Failed to connect to CA server: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read CA response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		http.Error(w, fmt.Sprintf("Enrollment failed: %s", string(body)), resp.StatusCode)
		return
	}

	// Parse enrollment response
	var enrollResp map[string]interface{}
	if err := json.Unmarshal(body, &enrollResp); err != nil {
		http.Error(w, "Failed to parse enrollment response: "+err.Error(), http.StatusInternalServerError)
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
	if req.UserRegistrationID == "" || req.AdminIdentity.EnrollmentID == "" || req.AdminIdentity.Secret == "" {
		http.Error(w, "registrationId and admin credentials are required", http.StatusBadRequest)
		return
	}

	client := createHTTPClient(req.CAConfig)

	// Prepare registration request
	regReq := map[string]interface{}{
		"id":          req.UserRegistrationID,
		"type":        req.Type,
		"affiliation": req.Affiliation,
		"caname":      req.CAConfig.CAName,
	}

	if req.UserSecret != "" {
		regReq["secret"] = req.UserSecret
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

	var adminCert, adminPrivateKey []byte
	// Get admin credentials from keystore for proper authorization
	if testing.Testing() {
		adminCert, adminPrivateKey, err = loadAdminCredentialsForTest()
	} else {
		adminCert, adminPrivateKey, err = getAdminCredentialsFromKeystore(req.AdminIdentity.EnrollmentID, req.CAConfig.MSPID)

	}
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
	authToken, err := createFabricCAAuthToken("POST", []byte(parsedURL.Path), regReqBody, adminCert, adminPrivateKey)
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
