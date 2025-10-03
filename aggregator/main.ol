from .keycloak.keycloak import Keycloak
from file import File
from .blockchainAPI.CAClient import CAClient
from .blockchainAPI.blockchainClient import BlockchainAPI
from console import Console
from string_utils import StringUtils

interface AggregatorInterface {
    RequestResponse: 
        executeTransaction(TransactionRequest)(undefined) //TODO define proper response type
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



service Aggregator {
    embed Keycloak as Keycloak
    embed File as File
    embed CAClient as CAClient
    embed BlockchainAPI as BlockchainAPI
    embed StringUtils as StringUtils
    embed Console as Console

    execution: concurrent

    inputPort ip {
        location: "socket://localhost:8099"
        protocol: http {
            debug = false
            contentType = "json"
        }
        interfaces: AggregatorInterface
    }


	main {
       [executeTransaction(transactionReq)(transactionResponse) {
            getUserData@Keycloak(transactionReq.accessToken)(userInfo)            
            if (!is_defined(userInfo.attributes.bcsecret)) {
                createUser@CAClient(userInfo)(registerUserResponse)
                if (registerUserResponse.success) {
                    userInfo.attributes.bcsecret = registerUserResponse.secret
                    updateUserData@Keycloak({ token = transactionReq.accessToken, attributes = userInfo.attributes })(success)
                } else {
                    // handle registration failure
                    println@Console("User registration failed")()
                }
                executeTranReq << {
                    enrollmentId = userInfo.email
                    secret = userInfo.attributes.bcsecret
                    type = transactionReq.type
                    institution = userInfo.attributes.institution 
                    transaction << transactionReq.transaction
                }
                executeTransaction@BlockchainAPI(executeTranReq)(transactionResponse)
            } else {
                executeTranReq << {
                    enrollmentId = userInfo.email
                    secret = userInfo.attributes.bcsecret
                    type = transactionReq.transaction.type
                    institution = userInfo.attributes.institution 
                    transaction << transactionReq.transaction.transaction
                }
                executeTransaction@BlockchainAPI(executeTranReq)(transactionResponse)
            }
            
            
            println@Console("Transaction executed")()
            valueToPrettyString@StringUtils(transactionResponse)(responseStr)
            println@Console(responseStr)()
       }]
	}
}

