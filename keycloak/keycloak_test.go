package keycloak_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"blockchain-api/keycloak"
)

func requireEnv(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("skipping: env %s not set", k)
	}
	return v
}

// IMPORTANT: load .env via scripts or VS Code task
func TestGetVAToken(t *testing.T) {
	username := requireEnv(t, "KEYCLOAK_TEST_USERNAME")
	password := requireEnv(t, "KEYCLOAK_TEST_PWD")

	token, err := keycloak.GetVAToken(username, password)
	if err != nil {
		t.Fatalf("Failed to get access token: %v", err)
	}
	if token.AccessToken == "" {
		t.Fatal("Expected non-empty access token")
	}
}

func TestExchangeForCAToken(t *testing.T) {
	username := requireEnv(t, "KEYCLOAK_TEST_USERNAME")
	password := requireEnv(t, "KEYCLOAK_TEST_PWD")

	vaToken, err := keycloak.GetVAToken(username, password)
	if err != nil {
		t.Fatalf("Failed to get VA token: %v", err)
	}
	caToken, err := keycloak.ExchangeForCAToken(vaToken.AccessToken)
	if err != nil {
		t.Fatalf("Failed to exchange for CA token: %v", err)
	}
	if caToken.AccessToken == "" {
		t.Fatal("Expected non-empty CA access token")
	}
}

func TestGetCATokenFromCredentials(t *testing.T) {
	username := requireEnv(t, "KEYCLOAK_TEST_USERNAME")
	password := requireEnv(t, "KEYCLOAK_TEST_PWD")

	caToken, err := keycloak.GetCATokenFromCredentials(username, password)
	if err != nil {
		t.Fatalf("Failed to get CA token from credentials: %v", err)
	}
	if caToken.AccessToken == "" {
		t.Fatal("Expected non-empty CA access token")
	}
}

func TestGetUserProfileData(t *testing.T) {
	username := requireEnv(t, "KEYCLOAK_TEST_USERNAME")
	password := requireEnv(t, "KEYCLOAK_TEST_PWD")

	vaToken, err := keycloak.GetVAToken(username, password)
	if err != nil {
		t.Fatalf("Failed to get VA token: %v", err)
	}
	profile, err := keycloak.GetUserProfileData(vaToken.AccessToken)
	if err != nil {
		t.Fatalf("Failed to get user profile data: %v", err)
	}
	if profile.ID == "" || profile.Username == "" || profile.Email == "" {
		t.Fatal("Expected non-empty user profile data")
	}
}

func TestUpdateUserProfile(t *testing.T) {
	username := requireEnv(t, "KEYCLOAK_TEST_USERNAME")
	password := requireEnv(t, "KEYCLOAK_TEST_PWD")

	vaToken, err := keycloak.GetCATokenFromCredentials(username, password)
	if err != nil {
		t.Fatalf("Failed to get VA token: %v", err)
	}
	bcSecret := fmt.Sprintf("BcSecret_%d", time.Now().UnixNano())
	updateRequest := &keycloak.UpdateUserProfileRequest{
		Attributes: keycloak.UserAttributes{
			GivenName:   "Konstantinos",
			FamilyName:  "Filippopolitis",
			Institution: "Barcelona Supercomputing Center",
			BcSecret:    bcSecret,
		},
	}
	if err := keycloak.PutUserProfileData(vaToken.AccessToken, updateRequest); err != nil {
		t.Fatalf("Failed to update user profile: %v", err)
	}
	userProfile, err := keycloak.GetUserProfileData(vaToken.AccessToken)
	if err != nil {
		t.Fatalf("Failed to get updated user profile data: %v", err)
	}
	if userProfile.Attributes.BcSecret != bcSecret {
		t.Fatal("User profile data did not update as expected")
	}
}
