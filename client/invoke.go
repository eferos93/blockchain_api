package client

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

// InvokeWithBody handles chaincode invoke requests with a pre-parsed RequestBody.
func InvokeWithBody(w http.ResponseWriter, reqBody RequestBody, gateway *client.Gateway) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Println("Received Invoke request")
	network := gateway.GetNetwork(reqBody.ChannelId)
	contract := network.GetContract(reqBody.ChaincodeId)
	txn_proposal, err := contract.NewProposal(reqBody.Function, client.WithArguments(reqBody.Args...))
	if err != nil {
		http.Error(w, "Error creating txn proposal:"+err.Error(), http.StatusBadRequest)
		return
	}
	txn_endorsed, err := txn_proposal.Endorse()
	if err != nil {
		http.Error(w, "Error endorsing txn: "+err.Error(), http.StatusBadRequest)
		return
	}
	txn_committed, err := txn_endorsed.Submit()
	if err != nil {
		http.Error(w, "Error submitting transaction: "+err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Transaction ID : %s Response: %s", txn_committed.TransactionID(), txn_endorsed.Result())
}
