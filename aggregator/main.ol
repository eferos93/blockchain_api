from keycloak.keycloak import Keycloak

interface AggregatorInterface {
    RequestResponse: 
        executeTransaction(TransactionRequest)(TransactionResponse)
}

type Success {
    success: bool
    message: string
}

type TransactionRequest {
    accessToken: string
    transactionData: TransactionData
}

//TODO define TransactionData
type TransactionData: any
type TransactionResponse: any

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

            }
       }]
	}
}

