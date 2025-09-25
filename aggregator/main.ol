from keycloak.keycloak import Keycloak
from file import File
from .blockchainAPI.CAClient import CAClient

interface AggregatorInterface {
    RequestResponse: 
        executeTransaction(TransactionRequest)(TransactionResponse)
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
    embed File
    
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
                
                
            }
       }]
	}
}

