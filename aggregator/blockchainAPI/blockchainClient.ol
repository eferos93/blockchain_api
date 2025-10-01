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
    transaction: TransactionRequest
}

interface BlockchainAPIClientInterface {
    RequestResponse:
        initialize(InitializeRequest)(string)
        query(TransactionRequest)(undefined)
        invoke(TransactionRequest)(undefined)
        close()(string)
}

interface BlockchainServiceInterface {
    RequestResponse:
        executeTransaction(ExecuteTransaction)(undefined)
}


constants {
    BSCAPI = "socket://localhost:3000"
}

service BlockchainAPI {
    execution: concurrent

    outputPort BlockchainAPIClientPort {
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
            BlockchainAPI.location = BSCAPI
            initialize@BlockchainAPI(transactionReq.transaction)(initResponse)
            if (transactionReq.type == "query") {
                query@BlockchainAPIClientPort(transactionReq.transaction)(response)
            } else if (transactionReq.type == "invoke") {
                invoke@BlockchainAPIClientPort(transactionReq.transaction)(response)
            }
        }
    }
}