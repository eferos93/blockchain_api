package client_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"blockchain-api/client"
)

func getTestOrgSetup() client.OrgSetup {
	// Use test keys and certs from the identities folder
	base := "../../fabric/identities/blockClient/msp"
	return client.OrgSetup{
		OrgName:      "Bsc",
		MSPID:        "bscMSP",
		CryptoPath:   base,
		CertPath:     filepath.Join(base, "signcerts/cert.pem"),
		KeyPath:      filepath.Join(base, "keystore"),
		TLSCertPath:  filepath.Join(base, "tlscacerts/ca.crt"),
		PeerEndpoint: "dns:///localhost:9051",
		GatewayPeer:  "peer0.bsc.dt4h.com",
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
		t.Errorf("Expected 200 OK, got %d. Body: %s", rec.Code, rec.Body.String())
	}
}

func TestInvokeHandlerWithoutInit(t *testing.T) {
	req := httptest.NewRequest("POST", "/client/invoke", nil)
	rec := httptest.NewRecorder()
	client.InvokeHandler(rec, req)
	if rec.Code == http.StatusOK {
		t.Errorf("Expected error when invoking without initialization. Body: %s", rec.Body.String())
	}
}

func TestQueryHandlerWithoutInit(t *testing.T) {
	req := httptest.NewRequest("POST", "/client/query", nil)
	rec := httptest.NewRecorder()
	client.QueryHandler(rec, req)
	if rec.Code == http.StatusOK {
		t.Errorf("Expected error when querying without initialization. Body: %s", rec.Body.String())
	}
}

func TestInvokeHandlerAfterInit(t *testing.T) {
	org := getTestOrgSetup()
	// Initialize session
	body, _ := json.Marshal(org)
	initReq := httptest.NewRequest("POST", "/client/", bytes.NewReader(body))
	initRec := httptest.NewRecorder()
	client.ClientHandler(initRec, initReq)
	if initRec.Code != http.StatusOK {
		t.Fatalf("Initialization failed, got %d", initRec.Code)
	}

	// Prepare invoke request body (example from curls.txt)
	invokeBody := []byte(`{"chaincodeid":"dt4hCC","channelid":"dt4h","function":"LogQuery","args":["select metadata from test-dataset"]}`)
	invokeReq := httptest.NewRequest("POST", "/client/invoke", bytes.NewReader(invokeBody))
	invokeRec := httptest.NewRecorder()
	client.InvokeHandler(invokeRec, invokeReq)
	if invokeRec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for invoke after init, got %d; Message: %s", invokeRec.Code, invokeRec.Body.String())
	}
	t.Logf("Invoke Response: %s", invokeRec.Body.String())
}

func TestQueryHandlerAfterInit(t *testing.T) {
	org := getTestOrgSetup()
	// Initialize session
	body, _ := json.Marshal(org)
	initReq := httptest.NewRequest("POST", "/client/", bytes.NewReader(body))
	initRec := httptest.NewRecorder()
	client.ClientHandler(initRec, initReq)
	if initRec.Code != http.StatusOK {
		t.Fatalf("Initialization failed, got %d", initRec.Code)
	}

	// Prepare query request as GET with query parameters
	queryReq := httptest.NewRequest("GET", "/client/query?chaincodeid=dt4hCC&channelid=dt4h&function=GetUserHistory&args=blockclient", nil)
	queryRec := httptest.NewRecorder()
	client.QueryHandler(queryRec, queryReq)
	if queryRec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for query after init, got %d; Message: %s", queryRec.Code, queryRec.Body.String())
	}
	t.Logf("Query Response: %s", queryRec.Body.String())
}
