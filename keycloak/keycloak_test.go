package keycloak_test

import (
	"blockchain-api/keycloak"
	"testing"
)

const (
	testUsername = "kkech@athenarc.gr"
	password     = "123456"
)

func TestGetVAToken(t *testing.T) {
	token, err := keycloak.GetVAToken(testUsername, password)
	if err != nil {
		t.Fatalf("Failed to get access token: %v", err)
	}

	t.Logf("Response: %+v", token)

	if token.AccessToken == "" {
		t.Fatal("Expected non-empty access token")
	}
}

func TestExchangeForCAToken(t *testing.T) {
	vaToken, err := keycloak.GetVAToken(testUsername, password)
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
	caToken, err := keycloak.GetCATokenFromCredentials(testUsername, password)
	if err != nil {
		t.Fatalf("Failed to get CA token from credentials: %v", err)
	}

	if caToken.AccessToken == "" {
		t.Fatal("Expected non-empty CA access token")
	}
}

func TestGetUserProfileData(t *testing.T) {
	vaToken, err := keycloak.GetVAToken(testUsername, password)
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

	if len(profile.Attributes.GivenName) == 0 || len(profile.Attributes.FamilyName) == 0 {
		t.Fatal("Expected non-empty user attributes")
	}
}
