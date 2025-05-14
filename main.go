package main

import (
	"fmt"
	"net/http"
	"sync"

	clientapi "rest-api-go/client"

	"github.com/gorilla/mux"
)

// In-memory map to track initialized clients (concurrent safe)
var initializedClients sync.Map

// Middleware to check if client has accessed /client/ first
func requireInitialization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		val, ok := initializedClients.Load(clientIP)
		initialized := ok && val.(bool)
		if !initialized {
			http.Error(w, "You must POST to /client/ first", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	r := mux.NewRouter()

	// Group under /client
	clientRouter := r.PathPrefix("/client").Subrouter()

	// Wrap the original handler to mark client as initialized
	clientRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		initializedClients.Store(clientIP, true)
		clientapi.ClientHandler(w, r)
	}).Methods("POST")

	clientRouter.Handle("/invoke", requireInitialization(http.HandlerFunc(clientapi.InvokeHandler))).Methods("POST")
	clientRouter.Handle("/query", requireInitialization(http.HandlerFunc(clientapi.QueryHandler))).Methods("POST")

	clientRouter.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		initializedClients.Store(clientIP, false)
		clientapi.CloseHandler(w, r)
	}).Methods("POST")

	fmt.Println("Listening (http://localhost:3000/)...")
	http.ListenAndServe(":3000", r)
}
