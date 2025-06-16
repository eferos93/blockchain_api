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
	"rest-api-go/keystore"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Store the initialized OrgSetups per session token (thread-safe)
var orgSetupSessions sync.Map

var store *sessions.CookieStore

func init() {
	authKey, err := hex.DecodeString(os.Getenv("SESSION_AUTH_KEY"))
	if err != nil {
		log.Fatalf("Error decoding the authKey: %v", err)
	}
	encKey, err := hex.DecodeString(os.Getenv("SESSION_ENC_KEY"))
	if err != nil {
		log.Fatalf("Error decoding the encKey: %v", err)
	}

	if len(authKey) == 0 || len(encKey) == 0 {
		log.Fatal("SESSION_AUTH_KEY and SESSION_ENC_KEY environment variables must be set and non-empty.")
	}
	store = sessions.NewCookieStore(authKey, encKey)
}

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

	connection, err := grpc.NewClient(setup.PeerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func (setup OrgSetup) newIdentity() *identity.X509Identity {
	var certificate *x509.Certificate
	var err error

	if setup.UseKeystore {
		// Validate keystore configuration
		if setup.EnrollmentID == "" {
			panic(fmt.Errorf("enrollmentId is required when useKeystore is true"))
		}

		if keystore.GlobalKeystore == nil {
			panic(fmt.Errorf("global keystore not initialized - check server configuration"))
		}

		// Load from keystore
		certPath, _, err := keystore.GetKeyForFabricClient(setup.EnrollmentID, setup.MSPID)
		if err != nil {
			panic(fmt.Errorf("failed to load certificate from keystore: %v", err))
		}

		certificate, err = loadCertificate(certPath)
		if err != nil {
			panic(fmt.Errorf("failed to load certificate from keystore path: %v", err))
		}
		log.Printf("Successfully loaded certificate from keystore for enrollment ID: %s", setup.EnrollmentID)
	} else {
		// File-based loading (legacy/testing)
		if setup.CertPath == "" {
			panic(fmt.Errorf("certPath is required when useKeystore is false"))
		}
		certificate, err = loadCertificate(setup.CertPath)
		if err != nil {
			panic(fmt.Errorf("failed to load certificate from file: %v", err))
		}
		log.Printf("Loaded certificate from file: %s", setup.CertPath)
	}

	id, err := identity.NewX509Identity(setup.MSPID, certificate)
	if err != nil {
		panic(fmt.Errorf("failed to create X509 identity: %v", err))
	}

	return id
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func (setup OrgSetup) newSign() identity.Sign {
	var privateKeyPEM []byte
	var err error

	if setup.UseKeystore {
		// Validate keystore configuration
		if setup.EnrollmentID == "" {
			panic(fmt.Errorf("enrollmentId is required when useKeystore is true"))
		}

		if keystore.GlobalKeystore == nil {
			panic(fmt.Errorf("global keystore not initialized - check server configuration"))
		}

		// Load from keystore
		_, keyDir, err := keystore.GetKeyForFabricClient(setup.EnrollmentID, setup.MSPID)
		if err != nil {
			panic(fmt.Errorf("failed to load private key from keystore: %v", err))
		}

		privateKeyPEM, err = loadPrivateKeyFromDirectory(keyDir)
		if err != nil {
			panic(fmt.Errorf("failed to load private key from keystore directory: %v", err))
		}
		log.Printf("Successfully loaded private key from keystore for enrollment ID: %s", setup.EnrollmentID)
	} else {
		// File-based loading (legacy/testing)
		if setup.KeyPath == "" {
			panic(fmt.Errorf("keyPath is required when useKeystore is false"))
		}
		privateKeyPEM, err = loadPrivateKeyFromDirectory(setup.KeyPath)
		if err != nil {
			panic(fmt.Errorf("failed to load private key from file: %v", err))
		}
		log.Printf("Loaded private key from file: %s", setup.KeyPath)
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(fmt.Errorf("failed to parse private key: %v", err))
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(fmt.Errorf("failed to create private key signer: %v", err))
	}

	return sign
}

// Helper function to load private key from directory
func loadPrivateKeyFromDirectory(keyDir string) ([]byte, error) {
	files, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key directory: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no files found in private key directory: %s", keyDir)
	}

	return os.ReadFile(path.Join(keyDir, files[0].Name()))
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
