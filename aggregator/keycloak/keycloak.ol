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
    given_name[1,*]: string
    family_name[1,*]: string
    institution[1,*]: string
    bcsecret[1,*]: string
}

type UserProfileData {
    id: string
    username: string
    email: string
    attributes: Attributes
}

type UpdateUserProfileRequest {
    attributes: Attributes
}

interface KeycloakServerInterface {
    RequestResponse:
        // GetVaToken(VATokenRequest)(VAToken),
        // GetCAToken(CATokenRequest)(CAToken),
        GetUserProfileData(void)(undefined),
        PutUserProfileData(UpdateUserProfileRequest)(undefined) //TODO define proper response type
}

type NewUserAttributes {
    token: string
    attributes: string
}

interface KeycloakServiceInterface {
    RequestResponse:
        isUserRegistered(string)(bool),
        updateUserData(NewUserAttributes)(bool),
        getUserData(string)(UserProfileData)
}

service Keycloak {
    execution: concurrent
    outputPort KeycloakServerPort {
        location: "socket://inb.bsc.es:443/"
        protocol: https {
            debug = true
            compression = false
            contentType = "application/json"
            format = "json"
            addHeader << {
                    // header[0] << "Content-Type" { value="application/json" }
                    header[0] << "Accept" { value="application/json" }
            }
            // osc.GetVaToken << {
            //     alias = "auth/realms/datatools4heart/protocol/openid-connect/token"
            //     method = "post"
            //     format = "x-www-form-urlencoded" //"application/x-www-form-urlencoded"
            //     // requestHeaders.("Accept") = "application/json"
            //     outHeaders.("Accept") = "application/json"
            // }
            // osc.GetCAToken << {
            //     alias = "auth/realms/datatools4heart/protocol/openid-connect/token"
            //     method = "post"
            //     format = "x-www-form-urlencoded" //"application/x-www-form-urlencoded"
            //     // addHeader.header[0] << { "Accept" { value = "application/json"} } this add headers both to request and response
            //     outHeaders.("Accept") = "application/json"
            // }
            osc.GetUserProfileData << {
                alias = "auth/realms/datatools4heart/account/"
                method = "get"
                // format = "json"
                // addHeader << {
                //     header[0] << "Accept" { value="application/json" }
                //     header[1] << "Authorization" { value="Bearer " + token }
                //     header[2] << "Content-Type" { value="application/json" }
                // }

            }
            osc.PutUserProfileData << {
                alias = "auth/realms/datatools4heart/account/"
                method = "post"
                // format = "json"
            }
        }
        interfaces: KeycloakServerInterface
    }

    inputPort KeycloakServicePort {
        location: "local"
        interfaces: KeycloakServiceInterface
    }

    main {
        isUserRegistered(token)(success) {
            KeycloakServerPort.protocol.https.addHeader.header[1] << "Authorization" { value="Bearer " + token }
            GetUserProfileData@KeycloakServerPort()(userProfileData)
            success = is_defined(userProfileData.attributes.bcsecret)
        }
        updateUserData(newUserAttr)(success) {
            KeycloakServerPort.protocol.https.addHeader.header[1] << "Authorization" { value="Bearer " + newUserAttr.token }
            PutUserProfileData@KeycloakServerPort({ attributes = newUserAttributes.attributes })(success)
        }
        getUserData(token)(userProfileData) {
            KeycloakServerPort.protocol.https.addHeader.header[1] << "Authorization" { value="Bearer " + token }
            GetUserProfileData@KeycloakServerPort()(userFullData)
            userProfileData << {
                id = userFullData.id
                username = userFullData.username
                email = userFullData.email
                attributes << userFullData.attributes
            }
        }
    }
}