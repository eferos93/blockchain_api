package keycloak

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
	keycloackURL                  = "https://inb.bsc.es/auth/realms/datatools4heart/protocol/openid-connect/token"
	keycloakUserInfoURL           = "https://inb.bsc.es/auth/realms/datatools4heart/account/"
	vaClientID                    = "va-webapp"
	caClientID                    = "dt4h-ca"
	caClientSecret                = "ZTZqz6wBXVV9wm8xtBkiEQEOPL9JGj5U"
	grantTypeTokenExchange        = "urn:ietf:params:oauth:grant-type:token-exchange"
	requestedTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

func GetVAToken(username, password string) (*VATokenResponse, error) {
	req, err := http.NewRequest("POST", keycloackURL, nil)
	if err != nil {
		return nil, err
	}

	data := url.Values{
		"client_id":  {vaClientID},
		"username":   {username},
		"password":   {password},
		"grant_type": {"password"},
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
		return nil, fmt.Errorf("failed to get token: %s", resp.Status)
	}

	var tokenResp VATokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func ExchangeForCAToken(vaToken string) (*VATokenResponse, error) {
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

	var tokenResp VATokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func GetCATokenFromCredentials(username, password string) (*VATokenResponse, error) {
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

	var profile UserProfileResponse
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, err
	}

	return &profile, nil
}
