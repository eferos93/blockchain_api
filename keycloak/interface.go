package keycloak

type VATokenRequest struct {
	ClientID  string `json:"clientId" form:"client_id"`
	Username  string `json:"username" form:"username"`
	Password  string `json:"password" form:"password"`
	GrantType string `json:"grantType" form:"grant_type"`
}

type VATokenResponse struct {
	AccessToken     string `json:"accessToken" form:"access_token"`
	TokenType       string `json:"tokenType" form:"token_type"`
	NotBeforePolicy int64  `json:"notBeforePolicy" form:"not-before-policy"`
	SessionState    string `json:"sessionState" form:"session_state"`
	Scope           string `json:"scope" form:"scope"`
}
