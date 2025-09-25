from file import File 

type AdminIdentity {
    enrollmentId: string
    secret: string
}

type Attribute {
    name: string
    value: string
}

type Response {
    success: bool
    message: string
    result {
        CA: any
        TLSCA: any //empty string for now
    }
}

type UserRegistrationData {
    adminIdentity: AdminIdentity
    userRegistrationId: string
    userSecret[0,1]: string
    type: string
    affiliation[0,1]: string
    attrs[0, *]: Attribute
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


interface CAServiceInterface {
    RequestResponse:
        registerUser()()
}

interface CAInterface {
    RequestResponse:
        registerUser(UserRegistrationData)(Response)
        enrollUser(UserEnrollmentRequest)(Response)
}

constants {
    ARCCALocation = "socket://localhost:8004"
    BSCCALocation = "socket://localhost:9004"
    UBCALocation = "socket://localhost:10004"
    ARCOrg = "Arc"
    BSCOrg = "Bsc"
    UBOrg = "Ub"
    adminIdentityFile = "adminIdentity.json"
}

service CAClient {
    execution: concurrent

    inputPort CAService {
        location: "local"
        interfaces: CAServiceInterface
    }

    outputPort CAClient {
        protocol: http
        interfaces: CAInterface
    }

    main {
        registerUser(userInfo)(registerUserResponse) {
            if (userInfo.attributes.institution == "Athena Research Center") {
                CAClient.location = ARCCALocation
                org -> ARCOrg
            } else if (userInfo.attributes.institution == "Barcelona Supercomputing Center") {
                CAClient.location = BSCCALocation
                org -> BSCOrg
            } else {
                CAClient.location = UBCALocation
                org -> UBOrg
            }
            readFile@File({ filename = adminIdentityFile, format = "json" })(adminId)
            userRegData << {
                adminIdentity << adminId
                userRegistrationId = userInfo.email
                type = "client"
                affiliation = affiliation
            }
            registerUser@CAClient(userRegData)(regResponse)


        }
    }
}

