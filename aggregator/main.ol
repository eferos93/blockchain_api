from keycloak.keycloak import Keycloak

interface AggregatorInterface {
    RequestResponse: 
        executeTransaction(TransactionRequest)(TransactionResponse)
}

interface CAClientInterface {
    RequestResponse:
        registerUser(UserRegistrationData)(Success)
}

type Success {
    success: bool
    message: string
}

type TransactionRequest {
    accessToken: string
    transactionData: TransactionData
}
type AdminIdentity {
    enrollmentId: string
    secret: string
}

type Attribute {
    name: string
    value: string
}

type UserRegistrationData {
    adminIdentity: AdminIdentity
    userRegistrationId: string
    userSecret: string
    type: string
    affiliation: string
    attrs[0, *]: Attributes
}

//TODO define TransactionData
type TransactionData: any
type TransactionResponse: any

constants {
    // ARCCALocation = "socket://blockchain1.imsi.athenarc.gr:8004"
    // BSCCALocation = "socket://blockchain1.imsi.athenarc.gr:9004"
    // UBCALocation = "socket://blockchain1.imsi.athenarc.gr:10004"
    ARCCALocation = "socket://localhost:8004"
    BSCCALocation = "socket://localhost:9004"
    UBCALocation = "socket://localhost:10004"
    ARCOrg = "Arc"
    BSCOrg = "Bsc"
    UBOrg = "Ub"
}

service Aggregator {
    embed Keycloak
    
    execution: concurrent

    outputPort blockchainAPI {
        location: "local"
        interfaces: BlockchainAPIInterface
    }

    outputPort CAClient {
        protocol: http
        interfaces: CAClientInterface
    }

    inputPort ip {
        location: "local"
        protocol: sodep
        interfaces: AggregatorInterface
    }


	main {
       [executeTransaction(transactionReq)(TransactionResponse) {
            isUserRegistered@Keycloak(transactionReq.accessToken)(isRegistered)
            if (!isRegistered) {
                getUserInfo@Keycloak(transactionReq.accessToken)(userInfo)
                if (userInfo.attributes.institution == "Athena Research Center") {
                    CAClient.location = ARCCALocation
                } else if (userInfo.attributes.institution == "Barcelona Supercomputing Center") {
                    CAClient.location = BSCCALocation
                } else {
                    CAClient.location = UBCALocation
                }

                registerUser@CAClient()()
            }
       }]
	}
}

