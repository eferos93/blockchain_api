package client_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"rest-api-go/client"
)

func getTestOrgSetup() client.OrgSetup {
	// Use test keys and certs from the identities folder
	base := "./identities/blockClient/msp"
	return client.OrgSetup{
		OrgName:      "blockClient",
		MSPID:        "blockClientMSP",
		CryptoPath:   base,
		CertPath:     filepath.Join(base, "signcerts/cert.pem"),
		KeyPath:      filepath.Join(base, "keystore"),
		TLSCertPath:  filepath.Join(base, "tlscacerts/ca.crt"),
		PeerEndpoint: "localhost:7051",
		GatewayPeer:  "peer0.blockClient.example.com",
	}
}

func TestInitialize(t *testing.T) {
	org := getTestOrgSetup()
	_, err := client.Initialize(org)
	if err != nil {
		t.Fatalf("Failed to initialize OrgSetup: %v", err)
	}
}

func TestClientHandler(t *testing.T) {
	org := getTestOrgSetup()
	body, _ := json.Marshal(org)
	req := httptest.NewRequest("POST", "/client/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	client.ClientHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", rec.Code)
	}
}

func TestInvokeHandlerWithoutInit(t *testing.T) {
	req := httptest.NewRequest("POST", "/client/invoke", nil)
	rec := httptest.NewRecorder()
	client.InvokeHandler(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("Expected error when invoking without initialization")
	}
}

func TestQueryHandlerWithoutInit(t *testing.T) {
	req := httptest.NewRequest("POST", "/client/query", nil)
	rec := httptest.NewRecorder()
	client.QueryHandler(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("Expected error when querying without initialization")
	}
}
