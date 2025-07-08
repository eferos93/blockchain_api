package caapi

import (
	"blockchain-api/keystore"
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
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

	// Parse CA info response
	var caInfoResp map[string]any
	if err := json.Unmarshal(body, &caInfoResp); err != nil {
		http.Error(w, "Failed to parse CA response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(caInfoResp)
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
	enrollReq := EnrollmentRequestREST{}
	var privateKey *ecdsa.PrivateKey
	var csrPEM string
	var err error
	// Add CSR if provided
	if req.CSRInfo.CN != "" {
		csrPEM, privateKey, err = generateCSR(req.CSRInfo)
		if err != nil {
			log.Printf("Failed to generate CSR: %v", err)
			http.Error(w, "Failed to generate CSR", http.StatusInternalServerError)
			return
		}

		// Set the CSR in the enrollment request
		enrollReq.CertificateRequest = csrPEM

	}

	if req.Profile != "" {
		enrollReq.Profile = &req.Profile
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
	var enrollResp map[string]any
	if err := json.Unmarshal(body, &enrollResp); err != nil {
		http.Error(w, "Failed to parse enrollment response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store the enrolled identity in keystore if enrollment was successful
	if result, ok := enrollResp["result"].(map[string]any); ok {
		certificatePEM, err := base64.StdEncoding.DecodeString(result["Cert"].(string))
		if err != nil {
			http.Error(w, "Failed to decode certificate from enrollment response", http.StatusInternalServerError)
			return
		}
		if err := keystore.StorePrivateKey(req.EnrollmentID, req.Secret, certificatePEM, privateKey); err != nil {
			log.Printf("Warning: Failed to store enrollment result in keystore: %v", err)
			// Don't fail the request, just log the warning
		} else {
			log.Printf("Successfully stored enrollment result for %s in keystore", req.EnrollmentID)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enrollResp)
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

	// Create HTTP client
	client := createHTTPClient(req.CAConfig)

	// Prepare registration request
	regReq := api.RegistrationRequest{
		Name:        req.UserRegistrationID,
		Type:        req.Type,
		Affiliation: req.Affiliation,
		CAName:      req.CAConfig.CAName,
	}

	if req.UserSecret != "" {
		regReq.Secret = req.UserSecret
	}

	if len(req.Attributes) > 0 {
		var attrs []api.Attribute
		for _, attr := range req.Attributes {
			attrs = append(attrs, api.Attribute{
				Name:  attr.Name,
				Value: attr.Value,
			})
		}
		regReq.Attributes = attrs
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
	if testing.Testing() {
		adminCert, adminPrivateKey, err = loadAdminCredentialsForTest()
	} else {
		adminCert, adminPrivateKey, err = getAdminCredentialsFromKeystore(req.AdminIdentity.EnrollmentID, req.CAConfig.MSPID, req.AdminIdentity.Secret)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve admin credentials: %v", err), http.StatusInternalServerError)
		return
	}

	// Create proper Fabric CA authorization token (keeping your existing auth token generation)
	authToken, err := createFabricCAAuthToken(factory.GetDefault(), regHttpReq.Method, regHttpReq.URL.RequestURI(), regReqBody, adminCert, adminPrivateKey)
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
	var registerResp map[string]any
	if err := json.Unmarshal(body, &registerResp); err != nil {
		http.Error(w, "Failed to parse registration response", http.StatusInternalServerError)
		return
	}

	// Return success response
	response := map[string]any{
		"success": true,
		"message": "Identity registered successfully",
		"result":  registerResp,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
