package main

import (
	"fmt"
	"net/http"

	clientapi "rest-api-go/client"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Group under /client
	clientRouter := r.PathPrefix("/client").Subrouter()

	clientRouter.HandleFunc("/", clientapi.ClientHandler).Methods("POST")
	clientRouter.HandleFunc("/invoke", clientapi.InvokeHandler).Methods("POST")
	clientRouter.HandleFunc("/query", clientapi.QueryHandler).Methods("POST")
	clientRouter.HandleFunc("/close", clientapi.CloseHandler).Methods("GET")

	fmt.Println("Listening (http://localhost:3000/)...")
	http.ListenAndServe(":3000", r)
}
