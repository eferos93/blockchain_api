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

type CATokenRequest struct {
	ClientID           string `json:"clientId" form:"client_id"`
	ClientSecret       string `json:"clientSecret" form:"client_secret"`
	GrantType          string `json:"grantType" form:"grant_type"`
	SubjectToken       string `json:"subjectToken" form:"subject_token"`
	RequestedTokenType string `json:"requestedTokenType" form:"requested_token_type"`
}

type UserAttributes struct {
	GivenName   string `json:"given_name"`
	FamilyName  string `json:"family_name"`
	Institution string `json:"institution"`
	PublicKey   string `json:"pbk"`  //base64
	Certificate string `json:"pkix"` //base64
	BcSecret    string `json:"bc_secret"`
}

type UpdateUserProfileRequest struct {
	Attributes UserAttributes `json:"attributes"`
}
