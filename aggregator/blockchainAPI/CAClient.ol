from file import File 

type AdminIdentity {
    enrollmentId: string
    secret: string
}

type Attribute {
    name: string
    value: string
}

type Error {
    code: int
    message: string
}

type Message {
    code: int
    message: string
}

type CAResponse {
    result[0, 1] {
        secret: string
    }
    success: bool
    errors[0, *]: Error
    messages[0, *]: Message
}

type RegisterResponse {
    success: bool
    message: string
    result {
        CA: CAResponse
        TLSCA: undefined //empty string for now
    }
}

type UserRegistrationData {
    adminIdentity: AdminIdentity
    userRegistrationId: string
    userSecret[0, 1]: string
    type: string
    affiliation[0,1 ]: string
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

type EnrollmentRequest {
    enrollmentId: string
    secret: string
    profile[0,1]: string
    csrInfo {
        cn: string //commonname
        names[0, *] {
            C: string //country
            ST: string //state or province
            L: string //locality or city
            O: string //organization
            OU: string //organizational unit
        }
        hosts[0, *]: string
    }
}

type EnrollResponse {
    CaEnrollResp {
        result {
            Cert: string
        
            ServerInfo {
                CAName: string
                CAChain: string
                IssuerPublicKey: string
                IssuerRevocationPublicKey: string
                Version: string
            }
        }
        success: bool 
        errors[0, *]: Error
        messages[0, *]: Message
    }
    TLSCAEnrollResp: string //empty string for now
    success: bool
}


type RegistrationResponse {
    success: bool
    secret?: string
}


interface CAServiceInterface {
    RequestResponse:
        createUser(UserProfileData)(RegistrationResponse)
}

interface CAInterface {
    RequestResponse:
        registerUser(UserRegistrationData)(RegisterResponse),
        enrollUser(EnrollmentRequest)(EnrollResponse)
}

constants {
    ARCCALocation = "socket://localhost:8004"
    BSCCALocation = "socket://localhost:9004"
    UBCALocation = "socket://localhost:10004"
    ARCOrg = "Arc"
    BSCOrg = "Bsc"
    UBOrg = "Ub"
    adminIdentityFile = "adminIdentity.json"
    bscName << {
        C = "ES"
        ST = "Catalunya"
        L = "Barcelona"
        O = "bsc"
    }
}

service CAClient {
    execution: concurrent

    inputPort CAService {
        location: "local"
        interfaces: CAServiceInterface
    }

    outputPort CAClient {
        protocol: http {
            format = "json"
            osc.registerUser << {
                alias = "fabricCA/register"
            }
            osc.enrollUser << {
                alias = "fabricCA/enroll"
            }
        }
        interfaces: CAInterface
    }

    main {
        createUser(userInfo)(registerUserResponse) {
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
            //TODO error handling
            enrollRequest << {
                enrollmentId -> userInfo.email
                secret -> regResponse.result.CA.result.secret
                csrInfo << {
                    cn -> userInfo.email
                    names[0] << {
                        C: bscName.C
                        ST: bscName.ST
                        L: bscName.L
                        O: org
                        OU: "client"
                    }
                    hosts[0] = "localhost"
                    hosts[1] = userInfo.email + org + ".dt4h.com"
                } 
            }
            enrollUser@CAClient(enrollRequest)(enrollmentResponse)

            registerUserResponse << {
                success = enrollmentResponse.success
                secret = regResponse.result.CA.result.secret
            }
        }
    }
}

