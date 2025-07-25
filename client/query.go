package client

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

// TODO: Add a new method to OrgSetup to accept RequestBody directly, do I really need this?
func QueryWithBody(w http.ResponseWriter, reqBody RequestBody, gateway *client.Gateway) {
	w.Header().Set("Content-type", "application/json")
	fmt.Println("Received Query request")
	chainCodeName := reqBody.ChaincodeId
	channelID := reqBody.ChannelId
	function := reqBody.Function
	args := reqBody.Args
	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
	network := gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)
	evaluateResponse, err := contract.EvaluateTransaction(function, args...)
	if err != nil {
		http.Error(w, "Query error from blockchain: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(evaluateResponse)
}
