type KeycloakServiceParams {
    location: string
}

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
    "not-before-policy": int // - is a special character, so it needs to be quoted
    session_state: string
    scope: string
}

type CAToken {
    access_token: string
    expires_in: int
    refresh_expires_in: int
    token_type: string
    id_token: string
    "not-before-policy": int // - is a special character, so it needs to be quoted
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


interface KeycloakServerInterface {
    RequestResponse:
        GetVaToken(VATokenRequest)(VAToken),
        GetCAToken(CATokenRequest)(CAToken),
        GetUserProfileData(void)(UserProfileData),
        PutUserProfileData(UpdateUserProfileRequest)(Success)
}

type Token: string 

type NewUserAttributes {
    token: Token
    attributes: string
}

interface KeycloakServiceInterface {
    RequestResponse:
        isUserRegistered(Token)(bool),
        updateUserData(NewUserAttributes)(bool),
        getUserData(Token)(UserProfileData)
}

service Keycloak {
    execution: concurrent
    outputPort KeycloakServerPort {
        location: "socket://inb.bsc.es/"
        protocol: https {
            osc.GetVaToken << {
                alias = "auth/realms/datatools4heart/protocol/openid-connect/token"
                method = "post"
                format = "x-www-form-urlencoded" //"application/x-www-form-urlencoded"
                requestHeaders.("Accept") = "application/json"
            }
            osc.GetCAToken << {
                alias = "auth/realms/datatools4heart/protocol/openid-connect/token"
                method = "post"
                format = "x-www-form-urlencoded" //"application/x-www-form-urlencoded"
                // addHeader.header[0] << { "Accept" { value = "application/json"} } this add headers both to request and response
                requestHeaders.("Accept") = "application/json"
            }
            osc.GetUserProfileData << {
                alias = "/auth/realms/datatools4heart/account/"
                method = "get"
                format = "json"
                requestHeaders.("Accept") = "application/json"
                requestHeaders.("Authorization") = "Bearer %!{token}"
            }
            osc.PutUserProfileData << {
                alias = "/auth/realms/datatools4heart/account/"
                method = "post"
                format = "json"
                requestHeaders.("Accept") = "application/json"
                requestHeaders.("Authorization") = "Bearer %!{token}"
            }
        }
        interfaces: KeycloakServerInterface
    }

    inputPort KeycloakServicePort {
        location: "local"
        interfaces: KeycloakServerInterface
    }

    main {
        isUserRegistered(token)(success) {
            GetUserProfileData@KeycloakServerPort()(userProfileData)
            success = is_defined(userProfileData.attributes.bcsecret)
        }
        updateUserData(newUserAttr)(success) {
            token -> newUserAttr.token
            PutUserProfileData@KeycloakServerPort({ attributes = newUserAttributes.attributes })(success)
        }
        getUserData(token)(userProfileData) {
            GetUserProfileData@KeycloakServerPort()(userProfileData)
        }
    }
}