package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	caapi "rest-api-go/ca"
	clientapi "rest-api-go/client"
	"rest-api-go/keystore"

	"github.com/gorilla/mux"
)

func main() {
	// Initialize keystore
	keystoreType := os.Getenv("KEYSTORE_TYPE")
	if keystoreType == "" {
		keystoreType = "file" // Default to file-based keystore
	}

	keystoreConfig := os.Getenv("KEYSTORE_CONFIG")
	if keystoreConfig == "" {
		keystoreConfig = "./secure-keystore" // Default path
	}

	keystorePassword := os.Getenv("KEYSTORE_PASSWORD")
	if keystorePassword == "" {
		log.Fatal("KEYSTORE_PASSWORD environment variable must be set")
	}

	if err := keystore.InitializeKeystore(keystoreType, keystoreConfig, keystorePassword); err != nil {
		log.Fatalf("Failed to initialize keystore: %v", err)
	}

	log.Printf("Keystore initialized: type=%s, config=%s", keystoreType, keystoreConfig)

	r := mux.NewRouter()

	// Group under /client
	clientRouter := r.PathPrefix("/client").Subrouter()

	clientRouter.HandleFunc("/", clientapi.ClientHandler).Methods("POST")
	clientRouter.HandleFunc("/invoke", clientapi.InvokeHandler).Methods("POST")
	clientRouter.HandleFunc("/query", clientapi.QueryHandler).Methods("GET")
	clientRouter.HandleFunc("/close", clientapi.CloseHandler).Methods("GET")

	// Group under /fabricCA
	caRouter := r.PathPrefix("/fabricCA").Subrouter()
	caRouter.HandleFunc("/enroll", caapi.EnrollHandler).Methods("POST")
	caRouter.HandleFunc("/register", caapi.RegisterHandler).Methods("POST")
	caRouter.HandleFunc("/info", caapi.InfoHandler).Methods("POST")

	fmt.Println("Listening (http://localhost:3000/)...")
	http.ListenAndServe(":3000", r)
}
