interface AggregatorInterface {
    RequestResponse: hello(void)(string)
}

service Aggregator {
    execution: concurrent
    inputPort ip {
        location: "local"
        protocol: sodep
        interfaces: AggregatorInterface
    }
	main {
        [hello()(res) { res = "World" }]
	}
}

