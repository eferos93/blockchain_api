package caapi

import (
	"blockchain-api/keystore"
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"

	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-lib-go/bccsp/factory"
)

var FabricCAConfig CAConfig
var TLSCAConfig CAConfig
var CAClient *http.Client
var TLSCAClient *http.Client

const (
	CAInfoEndpoint     = "%s/api/v1/cainfo"
	CAEnrollEndpoint   = "%s/api/v1/enroll"
	CARegisterEndpoint = "%s/api/v1/register"
)

func init() {
	FabricCAConfig = CAConfig{
		CAURL:   getEnvWithDefault("FABRIC_CA_URL", "http://localhost:10055"),
		CAName:  getEnvWithDefault("FABRIC_CA_NAME", "ca-bsc"),
		MSPID:   getEnvWithDefault("FABRIC_CA_MSPID", "BscMSP"),
		SkipTLS: getEnvWithDefault("FABRIC_CA_SKIP_TLS", "false") == "true",
	}
	TLSCAConfig = CAConfig{
		CAURL:   getEnvWithDefault("TLS_CA_URL", "http://localhost:10054"),
		CAName:  getEnvWithDefault("TLS_CA_NAME", "tlsca-bsc"),
		MSPID:   getEnvWithDefault("TLS_CA_MSPID", "BscMSP"),
		SkipTLS: getEnvWithDefault("TLS_CA_SKIP_TLS", "false") == "true",
	}
	CAClient = createHTTPClient(FabricCAConfig)
	TLSCAClient = createHTTPClient(TLSCAConfig)
}

// Handler for /fabricCA/info - Get CA information
func InfoHandler(w http.ResponseWriter, r *http.Request) {
	infoURL := fmt.Sprintf(CAInfoEndpoint, FabricCAConfig.CAURL)
	if FabricCAConfig.CAName != "" {
		infoURL += "?ca=" + FabricCAConfig.CAName
	}

	resp, err := CAClient.Get(infoURL)
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
	var csrPEM string
	var privateKey *ecdsa.PrivateKey
	var err error
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid enrollment request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.EnrollmentID == "" || req.Secret == "" {
		http.Error(w, "enrollmentId and secret are required", http.StatusBadRequest)
		return
	}

	// Prepare enrollment request for CA
	// Add CSR if provided
	if req.CSRInfo.CN != "" {
		csrPEM, privateKey, err = generateCSR(req.CSRInfo)
		if err != nil {
			log.Printf("Failed to generate CSR: %v", err)
			http.Error(w, "Failed to generate CSR", http.StatusInternalServerError)
			return
		}
	}

	CAreqBody, err := prepareEnrollRequest(req, w, false, csrPEM)
	if err != nil {
		http.Error(w, "Failed to prepare enrollment request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	TLSCAreqBody, err := prepareEnrollRequest(req, w, true, csrPEM)
	if err != nil {
		http.Error(w, "Failed to prepare TLS enrollment request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Make enrollment request to CA
	enrollCAURL := fmt.Sprintf(CAEnrollEndpoint, FabricCAConfig.CAURL)
	if FabricCAConfig.CAName != "" {
		enrollCAURL += "?ca=" + FabricCAConfig.CAName
	}

	enrollTLSCAURL := fmt.Sprintf(CAEnrollEndpoint, TLSCAConfig.CAURL)
	if TLSCAConfig.CAName != "" {
		enrollTLSCAURL += "?ca=" + TLSCAConfig.CAName
	}

	TLSCAEnrollBody, shouldReturn := sendEnrollRequest(enrollTLSCAURL, TLSCAreqBody, w, req)
	CAEnrollBody, shouldReturn := sendEnrollRequest(enrollCAURL, CAreqBody, w, req)
	if shouldReturn {
		http.Error(w, "Failed to enroll identity", http.StatusInternalServerError)
		return
	}

	// Parse enrollment response
	CAenrollResp, CAcertificatePEM, shouldReturn := parseResponse(CAEnrollBody, w)
	TLSCAEnrollResp, TLSCAcertificatePEM, shouldReturn := parseResponse(TLSCAEnrollBody, w)
	if shouldReturn {
		return
	}

	if err := keystore.StorePrivateKey(req.EnrollmentID, req.Secret, CAcertificatePEM, TLSCAcertificatePEM, privateKey); err != nil {
		log.Printf("Warning: Failed to store enrollment result in keystore: %v", err)
		// Don't fail the request, just log the warning
	} else {
		log.Printf("Successfully stored enrollment result for %s in keystore", req.EnrollmentID)
	}

	w.Header().Set("Content-Type", "application/json")
	var response = map[string]any{
		"CAEnrollResp":    CAenrollResp,
		"TLSCAEnrollResp": TLSCAEnrollResp,
		"success":         true,
	}
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

	// Prepare registration request
	regReq := api.RegistrationRequest{
		Name:        req.UserRegistrationID,
		Type:        req.Type,
		Affiliation: req.Affiliation,
		CAName:      FabricCAConfig.CAName,
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
	registerURL := fmt.Sprintf(CARegisterEndpoint, FabricCAConfig.CAURL)
	if FabricCAConfig.CAName != "" {
		registerURL += "?ca=" + FabricCAConfig.CAName
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
		adminCert, adminPrivateKey, err = getAdminCredentialsFromKeystore(req.AdminIdentity.EnrollmentID, FabricCAConfig.MSPID, req.AdminIdentity.Secret)
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

	regResp, err := CAClient.Do(regHttpReq)
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
