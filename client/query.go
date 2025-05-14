package client

import (
	"fmt"

	// "invoke" // Assuming invoke.go is in the same package
	"net/http"
)

// Query handles chaincode query requests.
// func (setup *OrgSetup) Query(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-type", "application/json")
// 	fmt.Println("Received Query request")
// 	dec := json.NewDecoder(r.Body)
// 	dec.DisallowUnknownFields()
// 	var reqBody RequestBody
// 	if err := dec.Decode(&reqBody); err != nil {
// 		fmt.Fprintf(w, "Decode body error: %s", err)
// 		return
// 	}
// 	chainCodeName := reqBody.ChaincodeId
// 	channelID := reqBody.ChannelId
// 	function := reqBody.Function
// 	args := reqBody.Args
// 	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %s\n", channelID, chainCodeName, function, args)
// 	network := setup.Gateway.GetNetwork(channelID)
// 	contract := network.GetContract(chainCodeName)
// 	evaluateResponse, err := contract.EvaluateTransaction(function, args...)
// 	if err != nil {
// 		fmt.Fprintf(w, "Error: %s", err)
// 		return
// 	}
// 	w.Write(evaluateResponse)
// }

// Add a new method to OrgSetup to accept RequestBody directly
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
		fmt.Fprintf(w, "Error: %s", err)
		return
	}
	w.Write(evaluateResponse)
}
