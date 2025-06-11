package client

import "github.com/hyperledger/fabric-gateway/pkg/client"

// OrgSetup contains organization's config to interact with the network.
type OrgSetup struct {
	OrgName      string `json:"orgName"`
	MSPID        string `json:"mspId"`
	CryptoPath   string `json:"cryptoPath"`
	CertPath     string `json:"certPath"`
	KeyPath      string `json:"keyPath"`
	TLSCertPath  string `json:"tlsCertPath"`
	PeerEndpoint string `json:"peerEndpoint"`
	GatewayPeer  string `json:"gatewayPeer"`
	// New fields for keystore-based loading
	UseKeystore  bool   `json:"useKeystore"`  // If true, load from keystore instead of files
	EnrollmentID string `json:"enrollmentId"` // Required if UseKeystore is true
	Gateway      client.Gateway
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
