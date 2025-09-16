type VATokenRequest {
    client_id: string
    grant_type: string
    username: string
    password: string
}

type CATokenRequest {
    client_id: string
    client_secret: string
    grant_type: string
    subject_token: string 
    requested_token_type: string
}

type VAToken {
    access_token: string
    expires_in: int
    refresh_expires_in: int
    refresh_token: string
    token_type: string
    not-before-policy: int
    session_state: string
    scope: string
}

type CAToken {
    access_token: string
    expires_in: int
    refresh_expires_in: int
    token_type: string
    id_token: string
    not-before-policy: int
    session_state: string
    scope: string
}

type Attributes {
    given_name: string
    family_name: string
    institution: string
    bcsecret: string
}

type UserProfileData {
    id: string
    username: string
    email: string
    attributes: Attributes
}

