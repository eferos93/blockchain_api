package client

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

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

// Store the initialized OrgSetups per session token (thread-safe)
var orgSetupSessions sync.Map // map[string]*OrgSetup

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_AUTH_KEY")),
	[]byte(os.Getenv("SESSION_ENC_KEY")))

// Helper to compute SHA256 hash of PEM-encoded identity
func IdentityHashFromPEM(pem string) string {
	hash := sha256.Sum256([]byte(pem))
	return hex.EncodeToString(hash[:])
}

// Initialize the setup for the organization.
func Initialize(setup OrgSetup) (*OrgSetup, error) {
	log.Printf("Initializing connection for %s...\n", setup.OrgName)
	clientConnection := setup.newGrpcConnection()
	id := setup.newIdentity()
	sign := setup.newSign()

	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	setup.Gateway = *gateway
	log.Println("Initialization complete")
	return &setup, nil
}

// Initialize the setup for the organization and store in session map.
func InitializeWithSession(setup OrgSetup, session *sessions.Session, w http.ResponseWriter, r *http.Request) error {
	orgSetup, err := Initialize(setup)
	if err != nil {
		return err
	}
	// Use the gorilla session ID as the key
	orgSetupSessions.Store(session.ID, orgSetup)
	session.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true if using HTTPS
	}
	return session.Save(r, w)
}

// Get OrgSetup from session map
func GetOrgSetup(sessionID string) (*OrgSetup, bool) {
	val, ok := orgSetupSessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	return val.(*OrgSetup), true
}

// Remove OrgSetup from session map
func RemoveOrgSetup(sessionID string) {
	orgSetupSessions.Delete(sessionID)
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func (setup OrgSetup) newGrpcConnection() *grpc.ClientConn {
	certificate, err := loadCertificate(setup.TLSCertPath)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, setup.GatewayPeer)

	connection, err := grpc.Dial(setup.PeerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func (setup OrgSetup) newIdentity() *identity.X509Identity {
	certificate, err := loadCertificate(setup.CertPath)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(setup.MSPID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func (setup OrgSetup) newSign() identity.Sign {
	files, err := os.ReadDir(setup.KeyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := os.ReadFile(path.Join(setup.KeyPath, files[0].Name()))

	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// Handler for /client/invoke
func InvokeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "fabric-session")
	orgSetup, ok := GetOrgSetup(session.ID)
	if !ok {
		http.Error(w, "Fabric client not initialized for this session. Call /client/ first.", http.StatusBadRequest)
		return
	}
	var reqBody RequestBody
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	orgSetup.InvokeWithBody(w, reqBody)
}

// Handler for /client/query
func QueryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Parse query parameters
		chaincodeId := r.URL.Query().Get("chaincodeid")
		channelId := r.URL.Query().Get("channelid")
		function := r.URL.Query().Get("function")
		args := r.URL.Query()["args"]
		if chaincodeId == "" || channelId == "" || function == "" {
			http.Error(w, "Missing required query parameters", http.StatusBadRequest)
			return
		}
		session, _ := store.Get(r, "fabric-session")
		orgSetup, ok := GetOrgSetup(session.ID)
		if !ok {
			http.Error(w, "Fabric client not initialized for this session. Call /client/ first.", http.StatusBadRequest)
			return
		}
		reqBody := RequestBody{
			ChaincodeId: chaincodeId,
			ChannelId:   channelId,
			Function:    function,
			Args:        args,
		}
		orgSetup.QueryWithBody(w, reqBody)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Handler for /client/ (initializes connection to Fabric blockchain)
func ClientHandler(w http.ResponseWriter, r *http.Request) {
	var orgConfig OrgSetup
	if err := json.NewDecoder(r.Body).Decode(&orgConfig); err != nil {
		http.Error(w, "Invalid OrgSetup: "+err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := store.Get(r, "fabric-session")
	if err := InitializeWithSession(orgConfig, session, w, r); err != nil {
		http.Error(w, "Error initializing org: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Fabric client connection initialized successfully."))
}

// Handler for /client/close
func CloseHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "fabric-session")
	orgSetup, ok := GetOrgSetup(session.ID)
	if !ok {
		http.Error(w, "No active Fabric client connection for this session.", http.StatusBadRequest)
		return
	}
	err := orgSetup.Gateway.Close()
	if err != nil {
		http.Error(w, "Error closing Fabric client connection: "+err.Error(), http.StatusInternalServerError)
		return
	}
	RemoveOrgSetup(session.ID)
	session.Options.MaxAge = -1 // Invalidate session cookie
	session.Save(r, w)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Fabric client connection closed successfully."))
}
