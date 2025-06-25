package caapi_test

import (
	"blockchain-api/caapi"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInfoHandler(t *testing.T) {
	// Create a mock CA server
	mockCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/cainfo" {
			response := caapi.CAInfoResponse{
				Success: true,
				Result: caapi.CAInfo{
					CAName:  "ca.example.com",
					Version: "1.5.0",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer mockCA.Close()

	// Test request
	requestBody := map[string]interface{}{
		"caConfig": map[string]interface{}{
			"caUrl":   mockCA.URL,
			"caName":  "ca.example.com",
			"mspId":   "Org1MSP",
			"skipTls": true,
		},
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/fabricCA/info", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	caapi.InfoHandler(recorder, req)

	// Check response
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Errorf("Expected success true, got %v", response["success"])
	}
}

func TestEnrollHandler(t *testing.T) {
	// Create a mock CA server
	mockCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/enroll" && r.Method == "POST" {
			// Mock enrollment response
			response := map[string]interface{}{
				"success": true,
				"result": map[string]interface{}{
					"Cert": "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer mockCA.Close()

	// Test request
	requestBody := caapi.EnrollmentRequest{
		CAConfig: caapi.CAConfig{
			CAURL:   mockCA.URL,
			CAName:  "ca.example.com",
			MSPID:   "Org1MSP",
			SkipTLS: true,
		},
		EnrollmentID: "testuser",
		Secret:       "testpw",
		CSRInfo: caapi.CSRInfo{
			CN: "testuser",
		},
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/fabricCA/enroll", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	caapi.EnrollHandler(recorder, req)

	// Check response
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Errorf("Expected success true, got %v", response["success"])
	}
}

func TestRegisterHandler(t *testing.T) {
	// Create a mock CA server
	enrollCalled := false
	registerCalled := false

	mockCA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/enroll" && r.Method == "POST" {
			enrollCalled = true
			// Mock admin enrollment response
			response := map[string]interface{}{
				"success": true,
				"result": map[string]interface{}{
					"Cert": "-----BEGIN CERTIFICATE-----\nADMIN_CERT\n-----END CERTIFICATE-----",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else if r.URL.Path == "/api/v1/register" && r.Method == "POST" {
			registerCalled = true
			// Mock registration response
			response := map[string]interface{}{
				"success": true,
				"result": map[string]interface{}{
					"secret": "generated_secret",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer mockCA.Close()

	// Test request
	requestBody := caapi.RegistrationRequest{
		CAConfig: caapi.CAConfig{
			CAURL:   mockCA.URL,
			CAName:  "ca.example.com",
			MSPID:   "Org1MSP",
			SkipTLS: true,
		},
		AdminIdentity: caapi.AdminIdentity{
			EnrollmentID: "admin",
			Secret:       "adminpw",
		},
		UserRegistrationID: "newuser",
		Type:               "client",
		Affiliation:        "org1.department1",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/fabricCA/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	caapi.RegisterHandler(recorder, req)

	// Check response
	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	if !enrollCalled {
		t.Error("Expected admin enrollment to be called")
	}

	if !registerCalled {
		t.Error("Expected registration to be called")
	}

	var response map[string]interface{}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Errorf("Expected success true, got %v", response["success"])
	}
}

func TestEnrollHandler_MissingFields(t *testing.T) {
	// Test with missing enrollment ID
	requestBody := caapi.EnrollmentRequest{
		CAConfig: caapi.CAConfig{
			CAURL: "http://localhost:7054",
		},
		Secret: "testpw",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/fabricCA/enroll", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	caapi.EnrollHandler(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestRegisterHandler_MissingFields(t *testing.T) {
	// Test with missing admin credentials
	requestBody := caapi.RegistrationRequest{
		CAConfig: caapi.CAConfig{
			CAURL: "http://localhost:7054",
		},
		UserRegistrationID: "newuser",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/fabricCA/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	caapi.RegisterHandler(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}
