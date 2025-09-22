package keycloak_test

import (
	"blockchain-api/keycloak"
	"fmt"
	"testing"
	"time"
)

const (
	testUsername = "kkech@athenarc.gr"
	password     = "123456"
)

// IMPORTANT: RUN THIS TEST FILE USING THE VSCODE TASKS, OR RUN THE SCRIPT IN tests_scripts
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

func TestUpdateUserProfile(t *testing.T) {
	vaToken, err := keycloak.GetCATokenFromCredentials(testUsername, password)
	if err != nil {
		t.Fatalf("Failed to get VA token: %v", err)
	}

	randomSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	bcSecret := "BcSecret_" + randomSuffix
	updateRequest := &keycloak.UpdateUserProfileRequest{
		Attributes: keycloak.UserAttributes{
			GivenName:   "Konstantinos",
			FamilyName:  "Filippopolitis",
			Institution: "Athena Research Center",
			BcSecret:    bcSecret,
		},
	}

	err = keycloak.PutUserProfileData(vaToken.AccessToken, updateRequest)
	if err != nil {
		t.Fatalf("Failed to update user profile: %v", err)
	}

	userProfile, err := keycloak.GetUserProfileData(vaToken.AccessToken)
	if err != nil {
		t.Fatalf("Failed to get updated user profile data: %v", err)
	}

	if userProfile.Attributes.GivenName != "Konstantinos" ||
		userProfile.Attributes.FamilyName != "Filippopolitis" ||
		userProfile.Attributes.Institution != "Athena Research Center" ||
		userProfile.Attributes.BcSecret != bcSecret {
		t.Fatal("User profile data did not update as expected")
	}

	t.Log("User profile updated successfully")
}
