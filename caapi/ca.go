package caapi

import (
	"blockchain-api/keystore"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/hyperledger/fabric-ca/api"
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

	// Create Fabric CA client
	caClient, err := createFabricCAClient(req.CAConfig)
	if err != nil {
		log.Printf("Failed to create CA client: %v", err)
		http.Error(w, "Failed to create CA client", http.StatusInternalServerError)
		return
	}
	caInfoReq := api.GetCAInfoRequest{CAName: req.CAConfig.CAName}
	// Get CA info using the official client
	caInfo, err := caClient.GetCAInfo(&caInfoReq)
	if err != nil {
		log.Printf("Failed to get CA info: %v", err)
		http.Error(w, "Failed to connect to CA server", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(caInfo)
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

	// Create Fabric CA client
	caClient, err := createFabricCAClient(req.CAConfig)
	if err != nil {
		log.Printf("Failed to create CA client: %v", err)
		http.Error(w, "Failed to create CA client", http.StatusInternalServerError)
		return
	}

	// Create enrollment request
	enrollmentReq := &api.EnrollmentRequest{
		Name:   req.EnrollmentID,
		Secret: req.Secret,
	}

	// Add CSR if provided
	if req.CSRInfo.CN != "" {
		_, privateKey, err := generateCSR(req.CSRInfo)
		if err != nil {
			log.Printf("Failed to generate CSR: %v", err)
			http.Error(w, "Failed to generate CSR", http.StatusInternalServerError)
			return
		}

		// Store the private key for future use
		_ = privateKey

		// Set the CSR in the enrollment request
		enrollmentReq.CSR = &api.CSRInfo{
			CN:    req.CSRInfo.CN,
			Hosts: req.CSRInfo.Hosts,
		}

		// Convert CSRInfo.Names to the expected format
		if len(req.CSRInfo.Names) > 0 {
			for _, name := range req.CSRInfo.Names {
				enrollmentReq.CSR.Names = append(enrollmentReq.CSR.Names, csr.Name{
					C:  name.C,
					ST: name.ST,
					L:  name.L,
					O:  name.O,
					OU: name.OU,
				})
			}
		}
	}

	if req.Profile != "" {
		enrollmentReq.Profile = req.Profile
	}

	// Perform enrollment using the official client
	enrollmentResponse, err := caClient.Enroll(enrollmentReq)
	if err != nil {
		log.Printf("Failed to enroll identity: %v", err)
		http.Error(w, "Failed to enroll identity: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store the enrolled identity in keystore if enrollment was successful
	if enrollmentResponse.Identity != nil {
		// Create enrollment result for keystore storage
		enrollResult := map[string]any{
			"Cert": string(enrollmentResponse.Identity.GetECert().Cert()),
		}

		if err := keystore.StoreEnrollmentResult(req.EnrollmentID, req.CAConfig.MSPID, enrollResult); err != nil {
			log.Printf("Warning: Failed to store enrollment result in keystore: %v", err)
			// Don't fail the request, just log the warning
		} else {
			log.Printf("Successfully stored enrollment result for %s in keystore", req.EnrollmentID)
		}
	}

	// Return success response
	response := map[string]any{
		"success": true,
		"message": "Identity enrolled successfully",
		"result": map[string]any{
			"certificate": string(enrollmentResponse.Identity.GetECert().Cert()),
		},
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

	// Create Fabric CA client
	caClient, err := createFabricCAClient(req.CAConfig)
	if err != nil {
		log.Printf("Failed to create CA client: %v", err)
		http.Error(w, "Failed to create CA client", http.StatusInternalServerError)
		return
	}

	// Get admin credentials and create admin identity
	var adminCert, adminPrivateKey []byte
	if testing.Testing() {
		adminCert, adminPrivateKey, err = loadAdminCredentialsForTest()
	} else {
		adminCert, adminPrivateKey, err = getAdminCredentialsFromKeystore(req.AdminIdentity.EnrollmentID, req.CAConfig.MSPID)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve admin credentials: %v", err), http.StatusInternalServerError)
		return
	}

	// Create admin identity using the credential package
	// adminIdentity, err := credential.NewCredential(adminPrivateKey, adminCert, caClient)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create admin identity: %v", err), http.StatusInternalServerError)
		return
	}

	// Set the admin identity for the client
	// caClient.SetIdentity(adminIdentity)

	// Create registration request
	regReq := &api.RegistrationRequest{
		Name:        req.UserRegistrationID,
		Type:        req.Type,
		Affiliation: req.Affiliation,
		CAName:      req.CAConfig.CAName,
	}

	if req.UserSecret != "" {
		regReq.Secret = req.UserSecret
	}

	// Convert attributes to the expected format
	if len(req.Attributes) > 0 {
		for _, attr := range req.Attributes {
			regReq.Attributes = append(regReq.Attributes, api.Attribute{
				Name:  attr.Name,
				Value: attr.Value,
			})
		}
	}

	// Perform registration using the official client
	// TODO: seems the fabric-ca-client does not support registration directly, so we use the lib.Client

	// secret, err := caClient.Register(regReq)

	registrationReq := &api.RegistrationRequest{
		Name:        req.UserRegistrationID,
		Type:        req.Type,
		Affiliation: req.Affiliation,
		CAName:      req.CAConfig.CAName,
		Secret:      req.UserSecret,
		Attributes:  regReq.Attributes,
	}

	registrationReqJSON, err := json.Marshal(registrationReq)
	if err != nil {
		log.Printf("Failed to marshal registration request: %v", err)
		http.Error(w, "Failed to marshal registration request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	httpRegisterReq, err := http.NewRequest("POST", req.CAConfig.CAURL+"/api/v1/register/ca="+req.CAConfig.CAName, bytes.NewBuffer(registrationReqJSON))
	httpRegisterReq.Header.Set("Content-Type", "application/json")
	authToken, err := createFabricCAAuthToken(caClient.GetCSP(), "POST", httpRegisterReq.URL.Path, registrationReqJSON, adminCert, adminPrivateKey)
	if err != nil {
		log.Printf("Failed to create Fabric CA auth token: %v", err)
		http.Error(w, "Failed to create Fabric CA auth token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	httpRegisterReq.Header.Set("Authorization", authToken)

	var secret any
	caClient.SendReq(httpRegisterReq, secret)
	if err != nil {
		log.Printf("Failed to register identity: %v", err)
		http.Error(w, "Failed to register identity: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return success response
	response := map[string]any{
		"success": true,
		"message": "Identity registered successfully",
		"result": map[string]any{
			"secret": secret,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
