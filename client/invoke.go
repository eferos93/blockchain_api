package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

// Invoke handles chaincode invoke requests.
func (setup *OrgSetup) Invoke(w http.ResponseWriter, r *http.Request, gateway *client.Gateway) {
	w.Header().Set("Content-Type", "application/json")

	fmt.Println("Received Invoke request")
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqBody RequestBody
	if err := dec.Decode(&reqBody); err != nil {
		fmt.Fprintf(w, "Decode body error: %s", err)
		return
	}

	network := gateway.GetNetwork(reqBody.ChannelId)
	contract := network.GetContract(reqBody.ChaincodeId)
	txn_proposal, err := contract.NewProposal(reqBody.Function, client.WithArguments(reqBody.Args...))

	if err != nil {
		http.Error(w, "Error creating txn proposal: "+err.Error(), http.StatusBadRequest)
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
