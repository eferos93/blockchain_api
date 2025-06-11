package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hyperledger/fabric-gateway/pkg/client"
)

// Invoke handles chaincode invoke requests.
func (setup *OrgSetup) Invoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	fmt.Println("Received Invoke request")
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqBody RequestBody
	if err := dec.Decode(&reqBody); err != nil {
		fmt.Fprintf(w, "Decode body error: %s", err)
		return
	}

	network := setup.Gateway.GetNetwork(reqBody.ChannelId)
	contract := network.GetContract(reqBody.ChaincodeId)
	txn_proposal, err := contract.NewProposal(reqBody.Function, client.WithArguments(reqBody.Args...))

	if err != nil {
		fmt.Fprintf(w, "Error creating txn proposal: %s", err)
		return
	}
	txn_endorsed, err := txn_proposal.Endorse()
	if err != nil {
		fmt.Fprintf(w, "Error endorsing txn: %s", err)
		return
	}
	txn_committed, err := txn_endorsed.Submit()
	if err != nil {
		fmt.Fprintf(w, "Error submitting transaction: %s", err)
		return
	}
	fmt.Fprintf(w, "Transaction ID : %s Response: %s", txn_committed.TransactionID(), txn_endorsed.Result())
}

// InvokeWithBody handles chaincode invoke requests with a pre-parsed RequestBody.
func (setup *OrgSetup) InvokeWithBody(w http.ResponseWriter, reqBody RequestBody) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Println("Received Invoke request")
	network := setup.Gateway.GetNetwork(reqBody.ChannelId)
	contract := network.GetContract(reqBody.ChaincodeId)
	txn_proposal, err := contract.NewProposal(reqBody.Function, client.WithArguments(reqBody.Args...))
	if err != nil {
		fmt.Fprintf(w, "Error creating txn proposal: %s", err)
		return
	}
	txn_endorsed, err := txn_proposal.Endorse()
	if err != nil {
		fmt.Fprintf(w, "Error endorsing txn: %s", err)
		return
	}
	txn_committed, err := txn_endorsed.Submit()
	if err != nil {
		fmt.Fprintf(w, "Error submitting transaction: %s", err)
		return
	}
	fmt.Fprintf(w, "Transaction ID : %s Response: %s", txn_committed.TransactionID(), txn_endorsed.Result())
}
