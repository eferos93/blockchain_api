
interface KeycloakServerInterface {
    RequestResponse:
        GetVaToken(VATokenRequest)(VAToken)
        GetCAToken(CATokenRequest)(CAToken)
        GetUserProfileData(void)(UserProfileData)
        PutUserProfileData(UpdateUserProfileRequest)(Success)
}

service Keycloak ( params : KeycloakServiceParams ) {
    execution: concurrent
    outputPort KeycloakServerPort {
        location: "socket://inb.bsc.es/"
        protocol: https {
            osc.GetVaToken << {
                alias = "auth/realms/datatools4heart/protocol/openid-connect/token"
                method = "post"
                format = "x-www-form-urlencoded" //"application/x-www-form-urlencoded"
                addHeader.header[0] << { "Accept" { value = "application/json"} }
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
                requestHeaders.("Accept") = "application/json"
                requestHeaders.("Authorization") = "Bearer %!{token}"
            }
            osc.PutUserProfileData << {
                alias = "/auth/realms/datatools4heart/account/"
                method = "get"
                format = "json"
                requestHeaders.("Accept") = "application/json"
                requestHeaders.("Authorization") = "Bearer %!{token}"
            }
        }
        interfaces: KeycloakServerInterface
    }

    inputPort KeycloakClientPort {
        location: "socket://" + params.location
    }
}

