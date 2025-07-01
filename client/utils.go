package client

import (
	"blockchain-api/keystore"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

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

// Helper to compute SHA256 hash of PEM-encoded identity
func IdentityHashFromPEM(pem string) string {
	hash := sha256.Sum256([]byte(pem))
	return hex.EncodeToString(hash[:])
}

// Initialize the setup for the organization.
func Initialize(setup OrgSetup) (*OrgSetup, error) {
	log.Printf("Initializing connection for %s...\n", setup.OrgName)
	clientConnection, err := setup.newGrpcConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}
	id, err := setup.newIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}
	sign, err := setup.newSign()
	if err != nil {
		return nil, fmt.Errorf("failed to create sign function: %w", err)
	}

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
		return nil, fmt.Errorf("failed to connect to gateway: %w", err)
	}
	setup.Gateway = *gateway
	log.Println("Initialization complete")
	return &setup, nil
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
func (setup OrgSetup) newGrpcConnection() (*grpc.ClientConn, error) {
	// TODO: implement TLS certificate loading from keystore if UseKeystore is true
	certificate, err := loadCertificate(setup.TLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, setup.GatewayPeer)

	connection, err := grpc.NewClient(setup.PeerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	return connection, nil
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func (setup OrgSetup) newIdentity() (*identity.X509Identity, error) {
	var certificate *x509.Certificate
	var certficatePEM []byte
	var err error

	if setup.UseKeystore && setup.EnrollmentID != "" {
		// Load from keystore
		certficatePEM, _, err = keystore.GetKeyForFabricClient(setup.EnrollmentID, setup.MSPID)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate from keystore: %w", err)
		}
		certificate, err = identity.CertificateFromPEM(certficatePEM)
	} else {
		// Load from file system
		certificate, err = loadCertificate(setup.CertPath)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	id, err := identity.NewX509Identity(setup.MSPID, certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to create X.509 identity: %w", err)
	}

	return id, nil
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func (setup OrgSetup) newSign() (identity.Sign, error) {
	var privateKeyPEM []byte
	var err error

	if setup.UseKeystore && setup.EnrollmentID != "" {
		// Load from keystore
		_, privateKeyPEM, err = keystore.GetKeyForFabricClient(setup.EnrollmentID, setup.MSPID)
		if err != nil {
			return nil, fmt.Errorf("failed to get key from keystore: %w", err)
		}
	} else {
		// Load from file system
		files, err := os.ReadDir(setup.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key directory: %w", err)
		}
		privateKeyPEM, err = os.ReadFile(path.Join(setup.KeyPath, files[0].Name()))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key PEM: %w", err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key sign: %w", err)
	}

	return sign, nil
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}
