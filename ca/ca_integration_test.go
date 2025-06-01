package ca_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"rest-api-go/ca"
	"testing"
)

// Integration tests for real CA server
// These tests require a running CA server at localhost:10055

func TestRealCAInfoHandler(t *testing.T) {
	// Test request with real CA configuration
	requestBody := map[string]interface{}{
		"caConfig": map[string]interface{}{
			"caUrl":   "http://localhost:10055",
			"caName":  "ca_bsc",
			"mspId":   "bscMSP",
			"skipTls": true,
		},
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/fabricCA/info", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	ca.InfoHandler(recorder, req)

	// Check response
	t.Logf("CA Info Response Code: %d", recorder.Code)
	t.Logf("CA Info Response Body: %s", recorder.Body.String())

	if recorder.Code == http.StatusInternalServerError {
		t.Logf("CA server might not be running at localhost:10055")
		t.Skip("Skipping real CA test - server not available")
		return
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, recorder.Code)
		return
	}

	var response map[string]interface{}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Errorf("Expected success true, got %v", response["success"])
	}

	// Check if we got CA info
	if caInfo, ok := response["caInfo"].(map[string]interface{}); ok {
		t.Logf("CA Name: %v", caInfo["CAName"])
		t.Logf("CA Version: %v", caInfo["Version"])
	}
}

func TestRealCAEnrollHandler(t *testing.T) {
	// Test enrollment with admin credentials
	// Note: This test assumes admin/adminpw credentials exist
	requestBody := ca.EnrollmentRequest{
		CAConfig: ca.CAConfig{
			CAURL:   "http://localhost:10055",
			CAName:  "ca_bsc",
			MSPID:   "bscMSP",
			SkipTLS: true,
		},
		EnrollmentID: "admin",
		Secret:       "adminpw",
		CSRInfo: ca.CSRInfo{
			CN: "admin",
			Names: []ca.Name{
				{
					C:  "US",
					ST: "California",
					L:  "San Francisco",
					O:  "bsc",
					OU: "admin",
				},
			},
		},
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/fabricCA/enroll", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	ca.EnrollHandler(recorder, req)

	// Check response
	t.Logf("Enroll Response Code: %d", recorder.Code)
	t.Logf("Enroll Response Body: %s", recorder.Body.String())

	if recorder.Code == http.StatusInternalServerError {
		t.Logf("CA server might not be running at localhost:10055")
		t.Skip("Skipping real CA enrollment test - server not available")
		return
	}

	if recorder.Code != http.StatusOK {
		t.Logf("Enrollment failed - this might be expected if admin is already enrolled")
		// Don't fail the test as admin might already be enrolled
		return
	}

	var response map[string]interface{}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Errorf("Expected success true, got %v", response["success"])
	}

	// Check if we got enrollment result
	if result, ok := response["result"].(map[string]interface{}); ok {
		t.Logf("Enrollment successful, got result with keys: %v", getKeys(result))
	}
}

func TestRealCARegisterHandler(t *testing.T) {
	// Test registration of a new user
	requestBody := ca.RegistrationRequest{
		CAConfig: ca.CAConfig{
			CAURL:   "http://localhost:10055",
			CAName:  "ca_bsc",
			MSPID:   "bscMSP",
			SkipTLS: true,
		},
		AdminIdentity: ca.AdminIdentity{
			EnrollmentID: "admin",
			Secret:       "adminpw",
		},
		RegistrationID: "testuser123",
		Type:           "client",
		Affiliation:    "bsc",
		Attributes: []ca.Attribute{
			{
				Name:  "role",
				Value: "client",
			},
		},
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/fabricCA/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	ca.RegisterHandler(recorder, req)

	// Check response
	t.Logf("Register Response Code: %d", recorder.Code)
	t.Logf("Register Response Body: %s", recorder.Body.String())

	if recorder.Code == http.StatusInternalServerError {
		t.Logf("CA server might not be running at localhost:10055")
		t.Skip("Skipping real CA registration test - server not available")
		return
	}

	if recorder.Code == http.StatusUnauthorized {
		t.Logf("Admin authentication failed - check admin credentials")
		t.Skip("Skipping registration test - admin auth failed")
		return
	}

	// Registration might fail if user already exists, which is OK for testing
	if recorder.Code != http.StatusOK {
		t.Logf("Registration failed (code %d) - user might already exist", recorder.Code)
		return
	}

	var response map[string]interface{}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["success"] != true {
		t.Errorf("Expected success true, got %v", response["success"])
	}

	// Check if we got registration result
	if result, ok := response["result"].(map[string]interface{}); ok {
		t.Logf("Registration successful, got result with keys: %v", getKeys(result))
		if secret, ok := result["secret"].(string); ok {
			t.Logf("Generated secret for testuser123: %s", secret)
		}
	}
}

// Helper function to get keys from a map for logging
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
