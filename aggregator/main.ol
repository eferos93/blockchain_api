from keycloak.keycloak import Keycloak
from file import File
from .blockchainAPI.CAClient import CAClient
from .blockchainAPI.blockchainClient import BlockchainAPI
from console import Console

interface AggregatorInterface {
    RequestResponse: 
        executeTransaction(TransactionRequest)(TransactionResponse)
}

type Transaction {
    chaincodeid: string
    channelid: string 
    function: string
    args[1, *]: string
}

type ExecuteTransaction {
    type: string( enum(["query", "invoke"]) )
    transaction: Transaction
}

type TransactionRequest {
    accessToken: string
    transaction: ExecuteTransaction
}

type TransactionResponse: any

service Aggregator {
    embed Keycloak
    embed File
    embed CAClient
    embed BlockchainAPI
    
    execution: concurrent

    outputPort blockchainAPI {
        location: "local"
        interfaces: BlockchainAPIInterface
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
                registerUser@CAClient(userInfo)(registerUserResponse)
                if (registerUserResponse.success) {
                    userInfo.attributes.bcsecret = registerUserResponse.secret
                    bcSecret -> registerUserResponse.secret
                    username -> userInfo.email
                    updateUserData@Keycloak({ token = transactionReq.accessToken, attributes = userInfo.attributes })(success)
                } else {
                    // handle registration failure
                }
            } else {
                getUserData@Keycloak(transactionReq.accessToken)(userInfo)
                bcSecret -> userInfo.attributes.bcsecret
                username -> userInfo.email
            }
            executeTransaction@BlockchainAPI({ enrollmentId = username, secret = bcSecret, transaction << transactionReq.transaction })(response)
            
            println@Console("Transaction executed")()
            
       }]
	}
}

