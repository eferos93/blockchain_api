
interface KeycloakServerInterface {
    RequestResponse:
        GetVaToken(VATokenRequest)(VAToken)
        GetCAToken(CATokenRequest)(CAToken)
        GetUserProfileData(void)(UserProfileData)
        PutUserProfileData(UpdateUserProfileRequest)(Success)
}

