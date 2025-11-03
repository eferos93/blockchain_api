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
        TLS: undefined //empty string for now
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
    given_name?: string
    family_name?: string
    institution?: string
    bcsecret?: string
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
    CAEnrollResp {
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
    // TODO: set correct CA locations, maybe better passing them when starting the servicd
    ARCCALocation = "socket://localhost:8004",
    BSCCALocation = "socket://blockchain-api-filestore:3000",
    UBCALocation = "socket://localhost:10004",
    ARCOrg = "arc",
    BSCOrg = "bsc",
    UBOrg = "ub",
    adminIdentityFile = "adminIdentity.json",
}

service CAClient {
    embed File as File 
    
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

    init {
        global.name << {
            bsc << {
                C = "ES"
                ST = "Catalunya"
                L = "Barcelona"
                O = "bsc"
            }
            ub << {
                C = "ES"
                ST = "Catalunya"
                L = "Barcelona"
                O = "ub"
            }
            arc << {
                C = "GR"
                ST = "Attica"
                L = "Athens"
                O = "athena"
            }
        }
        
    }

    define checkExistence 
    {
        match@StringUtils(transactionReq.institution {.regex = regex})(matchRes)
    }

    main {
        createUser(userInfo)(registerUserResponse) {
            regex = "(?i).*(athena).*"
            checkExistence 
            if (matchRes == 1) {
                CAClient.location = ARCCALocation
                org = ARCOrg
            }
            regex = "(?i).*(bsc|supercomputing).*"
            checkExistence 
            if (matchRes == 1) {
                CAClient.location = BSCCALocation
                org = BSCOrg
            }
            regex = "(?i).*(university|ub).*"
            checkExistence 
            if (matchRes == 1) {
                CAClient.location = UBCALocation
                org = UBOrg
            }
            //TODO error handling if no match
            readFile@File({ filename = adminIdentityFile, format = "json" })(adminId)
            userRegData << {
                adminIdentity << adminId
                userRegistrationId = userInfo.email
                type = "client"
                affiliation = "" //no need for affiliation here!!! 
            }
            registerUser@CAClient(userRegData)(regResponse)
            //TODO error handling
            enrollRequest << {
                enrollmentId -> userInfo.email
                secret -> regResponse.result.CA.result.secret
                csrInfo << {
                    cn -> userInfo.email
                    names[0] << {
                        C = global.name.( org ).C
                        ST = global.name.( org ).ST
                        L = global.name.( org ).L
                        O = org
                        OU = "client"
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

