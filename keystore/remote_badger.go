package keystore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RemoteBadgerKeystore implements KeystoreManager for remote BadgerDB via HTTP API
type RemoteBadgerKeystore struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// RemoteBadgerConfig contains configuration for remote BadgerDB connection
type RemoteBadgerConfig struct {
	BaseURL    string `json:"baseUrl"`    // Base URL of the remote BadgerDB API
	APIKey     string `json:"apiKey"`     // API key for authentication
	TimeoutSec int    `json:"timeoutSec"` // HTTP timeout in seconds (default: 30)
}

// APIRequest represents the request payload for remote BadgerDB operations
type APIRequest struct {
	EnrollmentID   string `json:"enrollmentId,omitempty"`
	MSPID          string `json:"mspId,omitempty"`
	PrivateKeyPEM  string `json:"privateKeyPem,omitempty"`
	CertificatePEM string `json:"certificatePem,omitempty"`
}

// APIResponse represents the response from remote BadgerDB API
type APIResponse struct {
	Success bool           `json:"success"`
	Message string         `json:"message,omitempty"`
	Data    *KeystoreEntry `json:"data,omitempty"`
	Keys    []string       `json:"keys,omitempty"` // For ListKeys response
	Error   string         `json:"error,omitempty"`
}

// NewRemoteBadgerKeystore creates a new remote BadgerDB keystore client
func NewRemoteBadgerKeystore(config RemoteBadgerConfig) (*RemoteBadgerKeystore, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("baseURL is required")
	}

	if config.APIKey == "" {
		return nil, fmt.Errorf("apiKey is required")
	}

	timeout := 30 * time.Second
	if config.TimeoutSec > 0 {
		timeout = time.Duration(config.TimeoutSec) * time.Second
	}

	return &RemoteBadgerKeystore{
		baseURL: config.BaseURL,
		apiKey:  config.APIKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// StoreKey stores an encrypted private key via remote BadgerDB API
func (r *RemoteBadgerKeystore) StoreKey(enrollmentID, mspID string, privateKeyPEM, certificatePEM []byte) error {
	request := APIRequest{
		EnrollmentID:   enrollmentID,
		MSPID:          mspID,
		PrivateKeyPEM:  privateKeyPEM,
		CertificatePEM: certificatePEM,
	}

	_, err := r.makeRequest("POST", "/keystore/store", request)
	return err
}

// RetrieveKey retrieves and decrypts a private key via remote BadgerDB API
func (r *RemoteBadgerKeystore) RetrieveKey(enrollmentID, mspID string) (*KeystoreEntry, error) {
	request := APIRequest{
		EnrollmentID: enrollmentID,
		MSPID:        mspID,
	}

	response, err := r.makeRequest("POST", "/keystore/retrieve", request)
	if err != nil {
		return nil, err
	}

	if response.Data == nil {
		return nil, fmt.Errorf("key not found for %s:%s", enrollmentID, mspID)
	}

	return response.Data, nil
}

// DeleteKey removes a key via remote BadgerDB API
func (r *RemoteBadgerKeystore) DeleteKey(enrollmentID, mspID string) error {
	request := APIRequest{
		EnrollmentID: enrollmentID,
		MSPID:        mspID,
	}

	_, err := r.makeRequest("DELETE", "/keystore/delete", request)
	return err
}

// ListKeys returns all stored key identifiers via remote BadgerDB API
func (r *RemoteBadgerKeystore) ListKeys() ([]string, error) {
	response, err := r.makeRequest("GET", "/keystore/list", APIRequest{})
	if err != nil {
		return nil, err
	}

	if response.Keys == nil {
		return []string{}, nil
	}

	return response.Keys, nil
}

// Close closes the HTTP client connections (no-op for HTTP client)
func (r *RemoteBadgerKeystore) Close() error {
	// HTTP client doesn't need explicit closing, but we can close idle connections
	if transport, ok := r.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

// makeRequest makes an HTTP request to the remote BadgerDB API
func (r *RemoteBadgerKeystore) makeRequest(method, endpoint string, payload APIRequest) (*APIResponse, error) {
	// Serialize payload
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := r.baseURL + endpoint
	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.apiKey)

	// Make request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var apiResponse APIResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for API errors
	if !apiResponse.Success {
		if apiResponse.Error != "" {
			return nil, fmt.Errorf("API error: %s", apiResponse.Error)
		}
		return nil, fmt.Errorf("API request failed: %s", apiResponse.Message)
	}

	// Check HTTP status
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, apiResponse.Error)
	}

	return &apiResponse, nil
}

// HealthCheck checks if the remote BadgerDB service is available
func (r *RemoteBadgerKeystore) HealthCheck() error {
	req, err := http.NewRequest("GET", r.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+r.apiKey)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote keystore service unhealthy (status: %d)", resp.StatusCode)
	}

	return nil
}
