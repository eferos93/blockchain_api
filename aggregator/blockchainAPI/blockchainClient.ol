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
        initialize(InitializeRequest)(undefined),
        query(TransactionRequest)(undefined),
        invoke(TransactionRequest)(string),
        close(undefined)(undefined)
}

interface BlockchainServiceInterface {
    RequestResponse:
        executeTransaction(ExecuteTransaction)(undefined)
}


constants {
    ARCLocation = "socket://localhost:7070", //TODO this will not work, because its an orderer, need to point to peer
    BSCCALocation = "socket://blockchain-api-filestore:3000",
    UBCALocation = "socket://localhost:9051"
}

service BlockchainAPI {
    embed Console as Console
    embed StringUtils as StringUtils

    execution: concurrent

    outputPort BlockchainAPIPort {
        protocol: http {
            format = "json"
            // contentType = "application/json"
            osc.initialize << {
                method = "post"
                alias = "client/"
            }
            osc.query << {
                method = "get"
                alias = "client/query"
            }
            osc.invoke << {
                method = "post"
                alias = "client/invoke"
            }
            osc.close << {
                method = "get"
                alias = "client/close"
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
                BlockchainAPIPort.location = ARCLocation
            } else if (transactionReq.institution == "Barcelona Supercomputing Center") {
                BlockchainAPIPort.location = BSCCALocation
            } else if (transactionReq.institution == "University of Barcelona") {
                BlockchainAPIPort.location = UBCALocation
            } else {
                // Handle unknown institution
                println@Console("Unknown institution: " + transactionReq.institution)()
                exit
            }
            initialize@BlockchainAPIPort({ enrollmentId = transactionReq.enrollmentId, secret = transactionReq.secret })(initResponse)
            if (transactionReq.type == "query") {
                query@BlockchainAPIPort(transactionReq.transaction)(response)
            } else if (transactionReq.type == "invoke") {
                invoke@BlockchainAPIPort(transactionReq.transaction)(response)
            }
            // valueToPrettyString@StringUtils(response)(responseStr)
            println@Console("Transaction response:")()
            println@Console(responseStr)()
        }
    }
}