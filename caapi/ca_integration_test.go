package caapi_test

import (
	"blockchain-api/caapi"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Integration tests for real CA server
// These tests require a running CA server at localhost:10055

func TestRealCAInfoHandler(t *testing.T) {
	// Test request with real CA configuration
	requestBody := map[string]any{
		"caConfig": map[string]any{
			"caUrl":   "https://localhost:10055",
			"caName":  "ca-bsc",
			"mspId":   "BscMSP",
			"skipTls": true,
		},
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("GET", "/fabricCA/info", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	caapi.InfoHandler(recorder, req)

	// Check response
	t.Logf("CA Info Response Code: %d", recorder.Code)
	t.Logf("CA Info Response Body: %s", recorder.Body.String())

	if recorder.Code == http.StatusInternalServerError {
		t.Fatalf("CA server might not be running at localhost:10055; HTTPCode: %d, Error: %s", recorder.Code, recorder.Body.String())
		return
	}

	if recorder.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d. Error: %s", http.StatusOK, recorder.Code, recorder.Body.String())
		return
	}

	var response map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Errorf("Expected success true, got %v", response["success"])
	}

	// Check if we got CA info
	if caInfo, ok := response["caInfo"].(map[string]any); ok {
		t.Logf("CA Name: %v", caInfo["CAName"])
		t.Logf("CA Version: %v", caInfo["Version"])
	}
}

func TestRealCARegisterAndEnrollFlow(t *testing.T) {
	// Combined test for register and enroll flow
	// This test follows the proper sequence: register -> enroll

	caConfig := caapi.CAConfig{
		CAURL:   "https://localhost:10055",
		CAName:  "ca-bsc",
		MSPID:   "BscMSP",
		SkipTLS: true,
	}

	// Step 1: Register a new user
	t.Log("=== Step 1: Registering new user ===")

	registerRequest := caapi.RegistrationRequest{
		CAConfig: caConfig,
		AdminIdentity: caapi.AdminIdentity{
			EnrollmentID: "registrar0",
			Secret:       "registrarpw",
		},
		UserRegistrationID: "testuser123",
		Type:               "client",
		Affiliation:        "bsc",
		Attributes: []caapi.Attribute{
			{
				Name:  "role",
				Value: "client",
			},
		},
	}

	regBody, _ := json.Marshal(registerRequest)
	regReq := httptest.NewRequest("POST", "/fabricCA/register", bytes.NewBuffer(regBody))
	regReq.Header.Set("Content-Type", "application/json")

	regRecorder := httptest.NewRecorder()
	caapi.RegisterHandler(regRecorder, regReq)

	// Check registration response
	t.Logf("Register Response Code: %d", regRecorder.Code)
	t.Logf("Register Response Body: %s", regRecorder.Body.String())

	if regRecorder.Code == http.StatusInternalServerError {
		t.Fatalf("CA server might not be running at localhost:10055; Error: %s", regRecorder.Body.String())
		// t.Logf("CA server might not be running at localhost:10055")
		// t.Skip("Skipping real CA test - server not available")
		return
	}

	if regRecorder.Code == http.StatusUnauthorized {
		t.Fatalf("Admin authentication failed; Error: %s", regRecorder.Body.String())
		return
	}

	var userSecret string
	if regRecorder.Code == http.StatusOK || regRecorder.Code == http.StatusCreated {
		var regResponse map[string]any
		if err := json.NewDecoder(regRecorder.Body).Decode(&regResponse); err != nil {
			t.Fatalf("Failed to decode registration response: %v", err)
		}

		if regResponse["success"] == true {
			if result, ok := regResponse["result"].(map[string]any); ok {
				if secret, ok := result["secret"].(string); ok {
					userSecret = secret
					t.Logf("Registration successful, got secret: %s", secret)
				}
			}
		}
	} else {
		t.Logf("Registration failed (code %d) - user might already exist, trying with default secret", regRecorder.Code)
		// If registration failed because user exists, try with a common default secret
		userSecret = "testuser123pw"
	}

	if userSecret == "" {
		userSecret = "testuser123pw" // fallback secret
		t.Logf("Using fallback secret: %s", userSecret)
	}

	// Step 2: Enroll the registered user
	t.Log("=== Step 2: Enrolling the registered user ===")

	enrollRequest := caapi.EnrollmentRequest{
		CAConfig:     caConfig,
		EnrollmentID: "testuser123",
		Secret:       userSecret,
		CSRInfo: caapi.CSRInfo{
			CN: "testuser123",
			Names: []caapi.Name{
				{
					C:  "US",
					ST: "California",
					L:  "San Francisco",
					O:  "bsc",
					OU: "client",
				},
			},
		},
	}

	enrollBody, _ := json.Marshal(enrollRequest)
	enrollReq := httptest.NewRequest("POST", "/fabricCA/enroll", bytes.NewBuffer(enrollBody))
	enrollReq.Header.Set("Content-Type", "application/json")

	enrollRecorder := httptest.NewRecorder()
	caapi.EnrollHandler(enrollRecorder, enrollReq)

	// Check enrollment response
	t.Logf("Enroll Response Code: %d", enrollRecorder.Code)
	t.Logf("Enroll Response Body: %s", enrollRecorder.Body.String())

	if enrollRecorder.Code == http.StatusInternalServerError {
		t.Logf("CA server might not be running at localhost:10055")
		t.Skip("Skipping enrollment test - server not available")
		return
	}

	if enrollRecorder.Code != http.StatusOK && enrollRecorder.Code != http.StatusCreated {
		t.Errorf("Enrollment failed with code %d: %s", enrollRecorder.Code, enrollRecorder.Body.String())
		return
	}

	var enrollResponse map[string]any
	if err := json.NewDecoder(enrollRecorder.Body).Decode(&enrollResponse); err != nil {
		t.Fatalf("Failed to decode enrollment response: %v", err)
	}

	if enrollResponse["success"] != true {
		t.Errorf("Expected enrollment success true, got %v", enrollResponse["success"])
		return
	}

	// Check if we got enrollment result with certificate
	if result, ok := enrollResponse["result"].(map[string]any); ok {
		t.Logf("Enrollment successful, got result with keys: %v", getKeys(result))

		// Check for certificate in the result
		if cert, ok := result["Cert"].(string); ok && cert != "" {
			t.Logf("Successfully received certificate (length: %d)", len(cert))
		} else {
			t.Error("No certificate found in enrollment result")
		}
	} else {
		t.Error("No result found in enrollment response")
	}

	t.Log("=== Register and Enroll flow completed successfully ===")
}

// Helper function to get keys from a map for logging
func getKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
