package client

import "github.com/hyperledger/fabric-gateway/pkg/client"

// OrgSetup contains organization's config to interact with the network.

type OrgSetup struct {
	OrgName string `json:"orgName"`
	MSPID   string `json:"mspId"`

	// File-based authentication (for testing/legacy)
	CryptoPath  string `json:"cryptoPath,omitempty"`  // Optional: for file-based auth
	CertPath    string `json:"certPath,omitempty"`    // Optional: for file-based auth
	KeyPath     string `json:"keyPath,omitempty"`     // Optional: for file-based auth
	TLSCertPath string `json:"tlsCertPath,omitempty"` // Optional: for TLS connection

	// Network connection
	PeerEndpoint string `json:"peerEndpoint"`
	GatewayPeer  string `json:"gatewayPeer"`

	// Keystore-based authentication (preferred)
	UseKeystore  bool   `json:"useKeystore"`            // If true, load from global keystore
	EnrollmentID string `json:"enrollmentId,omitempty"` // Required if UseKeystore is true

	// Internal
	Gateway client.Gateway `json:"-"` // Don't serialize
}

type ClientRequestBody struct {
	OrgSetup OrgSetup `json:"orgSetup"`
	Secret   string   `json:"secret"`
}

// Combined request for OrgSetup and transaction
// Used for /client/invoke and /client/query
// (RequestBody is defined in invoke/invoke.go)
type TransactionRequest struct {
	OrgSetup    OrgSetup    `json:"orgSetup"`
	RequestBody RequestBody `json:"requestBody"`
}

type RequestBody struct {
	ChaincodeId string   `json:"chaincodeid"`
	ChannelId   string   `json:"channelid"`
	Function    string   `json:"function"`
	Args        []string `json:"args"`
}
