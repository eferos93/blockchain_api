package keycloak

type VATokenRequest struct {
	ClientID  string `json:"clientId" form:"client_id"`
	Username  string `json:"username" form:"username"`
	Password  string `json:"password" form:"password"`
	GrantType string `json:"grantType" form:"grant_type"`
}

type VATokenResponse struct {
	AccessToken      string `json:"access_token" form:"access_token"`
	ExpiresIn        int64  `json:"expires_in" form:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in" form:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token" form:"refresh_token"`
	TokenType        string `json:"token_type" form:"token_type"`
	NotBeforePolicy  int64  `json:"not_before_policy" form:"not-before-policy"`
	SessionState     string `json:"session_state" form:"session_state"`
	Scope            string `json:"scope" form:"scope"`
}

type CATokenRequest struct {
	ClientID           string `json:"clientId" form:"client_id"`
	ClientSecret       string `json:"clientSecret" form:"client_secret"`
	GrantType          string `json:"grantType" form:"grant_type"`
	SubjectToken       string `json:"subjectToken" form:"subject_token"`
	RequestedTokenType string `json:"requestedTokenType" form:"requested_token_type"`
}

type CATokenResponse struct {
	AccessToken      string `json:"access_token" form:"access_token"`
	ExpiresIn        int64  `json:"expires_in" form:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in" form:"refresh_expires_in"`
	TokenType        string `json:"token_type" form:"token_type"`
	IDToken          string `json:"id_token" form:"id_token"`
	NotBeforePolicy  int64  `json:"not_before_policy" form:"not-before-policy"`
	SessionState     string `json:"session_state" form:"session_state"`
	Scope            string `json:"scope" form:"scope"`
}

type UserAttributes struct {
	GivenName   string `json:"given_name"`
	FamilyName  string `json:"family_name"`
	Institution string `json:"institution"`
	BcSecret    string `json:"bcsecret"`
}

type UserProfileResponse struct {
	ID         string         `json:"id"`
	Username   string         `json:"username"`
	Email      string         `json:"email"`
	Attributes UserAttributes `json:"attributes"`
}

type UpdateUserProfileRequest struct {
	Attributes UserAttributes `json:"attributes"`
}
