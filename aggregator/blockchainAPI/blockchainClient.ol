from console import Console 
from string_utils import StringUtils

type InitializeRequest {
    secret: string
    enrollmentId: string
}

type TransactionRequest {
    chaincodeid: string
    channelid: string 
    function: string
    args[1, *]: string
}

type ExecuteTransaction {
    enrollmentId: string
    secret: string
    type: string( enum(["query", "invoke"]) )
    institution: string( enum(["Athena Research Center", "Barcelona Supercomputing Center", "University of Barcelona"]) )
    transaction: TransactionRequest
}

interface BlockchainAPIClientInterface {
    RequestResponse:
        initialize(InitializeRequest)(string),
        query(TransactionRequest)(undefined),
        invoke(TransactionRequest)(undefined),
        close(undefined)(string)
}

interface BlockchainServiceInterface {
    RequestResponse:
        executeTransaction(ExecuteTransaction)(undefined)
}


constants {
    ARCLocation = "socket://localhost:7070", //TODO this will not work, because its an orderer, need to point to peer
    BSCCALocation = "socket://blockchain-api-filestore:8081",
    UBCALocation = "socket://localhost:9051"
}

service BlockchainAPI {
    embed Console as Console
    embed StringUtils as StringUtils

    execution: concurrent

    outputPort BlockchainAPI {
        protocol: http {
            format = "json"
            osc.initialize << {
                method = "post"
                alias = "/client/"
            }
            osc.query << {
                method = "get"
                alias = "/client/query"
            }
            osc.invoke << {
                method = "post"
                alias = "/client/invoke"
            }
            osc.close << {
                method = "get"
                alias = "/client/close"
            }
        }
        interfaces: BlockchainAPIClientInterface
    }

    inputPort BlockchainService  {
        location: "local"
        interfaces: BlockchainServiceInterface
    }

    main {
        executeTransaction(transactionReq)(response) {
            if (transactionReq.institution == "Athena Research Center") {
                BlockchainAPIClientPort.location = ARCLocation
            } else if (transactionReq.institution == "Barcelona Supercomputing Center") {
                BlockchainAPIClientPort.location = BSCCALocation
            } else if (transactionReq.institution == "University of Barcelona") {
                BlockchainAPIClientPort.location = UBCALocation
            }
            initialize@BlockchainAPI({ enrollmentId = transactionReq.enrollmentId, secret = transactionReq.secret })(initResponse)
            if (transactionReq.type == "query") {
                query@BlockchainAPI(transactionReq.transaction)(response)
            } else if (transactionReq.type == "invoke") {
                invoke@BlockchainAPI(transactionReq.transaction)(response)
            }
            valueToPrettyString@StringUtils(response)(responseStr)
            println@Console("Transaction response:")()
            println@Console(responseStr)()
        }
    }
}