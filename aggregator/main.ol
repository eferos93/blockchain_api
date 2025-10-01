from keycloak.keycloak import Keycloak
from file import File
from .blockchainAPI.CAClient import CAClient
from .blockchainAPI.blockchainClient import BlockchainAPI
from console import Console
from string_utils import StringUtils

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

//TODO define proper response type
type TransactionResponse: undefined

service Aggregator {
    embed Keycloak
    embed File
    embed CAClient
    embed BlockchainAPI
    embed StringUtils
    embed Console
    
    execution: concurrent

    inputPort ip {
        location: "socket://localhost:8099"
        protocol: http {
            debug = true
            contentType = "json"
        }
        interfaces: AggregatorInterface
    }


	main {
       [executeTransaction(transactionReq)(TransactionResponse) {
            isUserRegistered@Keycloak(transactionReq.accessToken)(isRegistered)
            if (!isRegistered) {
                getUserInfo@Keycloak(transactionReq.accessToken)(userInfo)
                createUser@CAClient(userInfo)(registerUserResponse)
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
            executeTransaction@BlockchainAPI({ enrollmentId = username, secret = bcSecret, institution = userInfo.attributes.institution, transaction << transactionReq.transaction })(response)
            
            println@Console("Transaction executed")()
            valueToPrettyString@StringUtils(response)(responseStr)
            println@Console(responseStr)()
       }]
	}
}

