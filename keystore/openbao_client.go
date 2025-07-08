package keystore

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// NewOpenBaoKeystore creates a new OpenBao keystore client
func NewOpenBaoKeystore(config OpenBaoConfig) (*OpenBaoKeystore, error) {
	if config.Address == "" {
		return nil, fmt.Errorf("address is required")
	}

	if config.Token == "" {
		return nil, fmt.Errorf("token is required")
	}

	if config.SecretPath == "" {
		config.SecretPath = "blockchain-keys/" // ✅ Correct path for KV v2
	}

	if config.UserPath == "" {
		config.UserPath = "auth/userpass/users/" // ✅ Correct
	}

	if config.LoginPath == "" {
		config.LoginPath = "auth/userpass/login/" // ✅ Fixed path
	}

	clientConfig := api.DefaultConfig()
	clientConfig.Address = config.Address

	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenBao client: %w", err)
	}

	client.SetToken(config.Token)

	return &OpenBaoKeystore{
		client:     client,
		secretPath: config.SecretPath,
		userPath:   config.UserPath,
		loginPath:  config.LoginPath,
	}, nil
}

// StoreKey stores an encrypted private key in OpenBao
func (o *OpenBaoKeystore) StoreKey(username, password string, privateKeyPEM, certificatePEM []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := o.authenticateUser(username, password)
	if err != nil {
		return fmt.Errorf("failed to authenticate user: %w", err)
	}
	// Prepare the secret data
	secretData := map[string]any{
		"enrollmentId": username,
		"privateKey":   base64.StdEncoding.EncodeToString(privateKeyPEM),
		"certificate":  base64.StdEncoding.EncodeToString(certificatePEM),
		"createdAt":    time.Now().Format(time.RFC3339),
	}

	_, err = o.client.KVv2("kv").Put(ctx, o.secretPath+username, secretData)
	if err != nil {
		return fmt.Errorf("failed to store key in OpenBao: %w", err)
	}

	return nil
}

// RetrieveKey retrieves a private key from OpenBao
func (o *OpenBaoKeystore) RetrieveKey(username, password string) (*KeystoreEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := o.authenticateUser(username, password)
	if err != nil {
		return nil, err
	}

	// Read the secret data
	secret, err := o.client.KVv2("kv").Get(ctx, o.secretPath+username)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key from OpenBao: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("key not found for user: %s", username)
	}

	privateKeyPEM, _ := base64.StdEncoding.DecodeString(secret.Data["privateKey"].(string))
	certificatePEM, _ := base64.StdEncoding.DecodeString(secret.Data["certificate"].(string))

	// ✅ Fixed: Parse the time string properly
	var createdAt time.Time
	if createdAtStr, ok := secret.Data["createdAt"].(string); ok {
		createdAt, _ = time.Parse(time.RFC3339, createdAtStr)
	}

	entry := &KeystoreEntry{
		EnrollmentID: username,
		PrivateKey:   privateKeyPEM,
		Certificate:  certificatePEM,
		CreatedAt:    createdAt,
	}

	return entry, nil
}

func (o *OpenBaoKeystore) DeleteKey(username, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := o.authenticateUser(username, password)
	if err != nil {
		return err
	}

	// Delete the secret data
	err = o.client.KVv2("kv").Delete(ctx, o.secretPath+username)
	if err != nil {
		return fmt.Errorf("failed to delete key from OpenBao: %w", err)
	}
	return nil
}

// Close performs cleanup (OpenBao client doesn't require explicit closing)
func (o *OpenBaoKeystore) Close() error {
	// OpenBao client doesn't require explicit closing
	return nil
}

// HealthCheck verifies OpenBao connection and authentication
func (o *OpenBaoKeystore) HealthCheck() error {
	// Check if we can read the seal status (requires basic auth)
	sealStatus, err := o.client.Sys().SealStatus()
	if err != nil {
		return fmt.Errorf("failed to connect to OpenBao: %w", err)
	}

	if sealStatus.Sealed {
		return fmt.Errorf("OpenBao is sealed")
	}

	// Try to list the secret engines to verify our token has permissions
	mounts, err := o.client.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to verify OpenBao permissions: %w", err)
	}

	// Check if our secret path exists or if we can access secret engines
	if mounts == nil {
		return fmt.Errorf("unable to access OpenBao secret engines")
	}

	return nil
}

func (o *OpenBaoKeystore) authenticateUser(username, password string) error {
	loginPath := o.loginPath + username // This will be "auth/userpass/login/username"

	response, err := o.client.Logical().Write(loginPath, map[string]any{
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("failed to authenticate with OpenBao: %w", err)
	}

	if response == nil || response.Auth == nil || response.Auth.ClientToken == "" {
		return fmt.Errorf("authentication failed for user %s", username)
	}

	o.client.SetToken(response.Auth.ClientToken)
	return nil
}

func (o *OpenBaoKeystore) CreateNewUser(username, password string) error {
	userPath := o.userPath + username // This will be "auth/userpass/users/username"

	_, err := o.client.Logical().Write(userPath, map[string]any{
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("failed to create new user in OpenBao: %w", err)
	}

	return nil
}
