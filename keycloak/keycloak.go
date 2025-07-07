package keycloak

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var keycloackClient *http.Client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For development only, use proper TLS in production
		},
	},
	Timeout: 30 * time.Second, // Set a reasonable timeout
}

const (
	keycloackURL                  string = "https://inb.bsc.es/auth/realms/datatools4heart/protocol/openid-connect/token"
	keycloakUserInfoURL           string = "https://inb.bsc.es/auth/realms/datatools4heart/account/"
	vaClientID                    string = "va-webapp"
	caClientID                    string = "dt4h-ca"
	caClientSecret                string = "ZTZqz6wBXVV9wm8xtBkiEQEOPL9JGj5U"
	grantTypePassword             string = "password"
	grantTypeTokenExchange        string = "urn:ietf:params:oauth:grant-type:token-exchange"
	requestedTokenTypeAccessToken string = "urn:ietf:params:oauth:token-type:access_token"
)

func GetVAToken(username, password string) (*VATokenResponse, error) {
	data := url.Values{
		"client_id":  {vaClientID},
		"username":   {username},
		"password":   {password},
		"grant_type": {grantTypePassword}, // Use the constant here too
	}

	// Create request with encoded form data in the body
	req, err := http.NewRequest("POST", keycloackURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := keycloackClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get token: %s", resp.Status)
	}

	var tokenResp VATokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func ExchangeForCAToken(vaToken string) (*CATokenResponse, error) {
	req, err := http.NewRequest("POST", keycloackURL, nil)
	if err != nil {
		return nil, err
	}

	data := url.Values{
		"client_id":            {caClientID},
		"client_secret":        {caClientSecret},
		"grant_type":           {grantTypeTokenExchange},
		"subject_token":        {vaToken},
		"requested_token_type": {requestedTokenTypeAccessToken},
	}

	req.PostForm = data
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := keycloackClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to exchange token: %s", resp.Status)
	}

	var tokenResp CATokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func GetCATokenFromCredentials(username, password string) (*CATokenResponse, error) {
	vaToken, err := GetVAToken(username, password)
	if err != nil {
		return nil, fmt.Errorf("failed to get VA token: %w", err)
	}

	caToken, err := ExchangeForCAToken(vaToken.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange for CA token: %w", err)
	}

	return caToken, nil
}

func GetUserProfileData(token string) (*UserProfileResponse, error) {
	req, err := http.NewRequest("GET", keycloakUserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := keycloackClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user profile: %s", resp.Status)
	}

	// First decode to a generic map
	var rawResponse map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rawResponse); err != nil {
		return nil, err
	}

	var profile UserProfileResponse = UserProfileResponse{
		ID:       rawResponse["id"].(string),
		Username: rawResponse["username"].(string),
		Email:    rawResponse["email"].(string),
		Attributes: UserAttributes{
			GivenName:   rawResponse["attributes"].(map[string]any)["given_name"].([]string),
			FamilyName:  rawResponse["attributes"].(map[string]any)["family_name"].([]string),
			Institution: rawResponse["attributes"].(map[string]any)["institution"].([]string),
			BcSecret:    rawResponse["attributes"].(map[string]any)["bcsecret"].([]string),
		},
	}

	return &profile, nil
}
