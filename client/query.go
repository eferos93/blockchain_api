package client

import (
	"fmt"
	"net/http"
)

// TODO: Add a new method to OrgSetup to accept RequestBody directly, do I really need this?
func (setup *OrgSetup) QueryWithBody(w http.ResponseWriter, reqBody RequestBody) {
	w.Header().Set("Content-type", "application/json")
	fmt.Println("Received Query request")
	chainCodeName := reqBody.ChaincodeId
	channelID := reqBody.ChannelId
	function := reqBody.Function
	args := reqBody.Args
	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
	network := setup.Gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)
	evaluateResponse, err := contract.EvaluateTransaction(function, args...)
	if err != nil {
		http.Error(w, "Error: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(evaluateResponse)
}
