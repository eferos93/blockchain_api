service BlockchainAPI {
    outputPort BlockchainAPIClientPort {
        protocol: https
        interfaces: BlockchainAPIClientInterface
    }

    main {
        
    }
}