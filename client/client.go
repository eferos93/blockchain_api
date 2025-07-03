package client

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/sessions"
)

// Store the initialized OrgSetups per session token (thread-safe)
var orgSetupSessions sync.Map

var store *sessions.CookieStore
var storeOnce sync.Once

// getSessionStore initializes the session store lazily
func getSessionStore() *sessions.CookieStore {
	storeOnce.Do(func() {
		authKey, err := hex.DecodeString(os.Getenv("SESSION_AUTH_KEY"))
		if err != nil {
			log.Fatalf("Error decoding the authKey: %v", err)
		}
		encKey, err := hex.DecodeString(os.Getenv("SESSION_ENC_KEY"))
		if err != nil {
			log.Fatalf("Error decoding the encKey: %v", err)
		}

		if len(authKey) == 0 || len(encKey) == 0 {
			log.Fatal("SESSION_AUTH_KEY and SESSION_ENC_KEY environment variables must be set and non-empty.")
		}
		store = sessions.NewCookieStore(authKey, encKey)
	})
	return store
}

// Initialize the setup for the organization and store in session map.
func InitializeWithSession(clientRequestBody ClientRequestBody, session *sessions.Session, w http.ResponseWriter, r *http.Request) error {

	orgSetup, err := Initialize(clientRequestBody.OrgSetup, clientRequestBody.Secret)
	if err != nil {
		return err
	}
	// Use the gorilla session ID as the key
	orgSetupSessions.Store(session.ID, orgSetup)
	session.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true if using HTTPS
	}
	return session.Save(r, w)
}

// Handler for /client/invoke
func InvokeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionStore().Get(r, "fabric-session")
	orgSetup, ok := GetOrgSetup(session.ID)

	if !ok {
		http.Error(w, "Fabric client not initialized for this session. Call /client/ first.", http.StatusBadRequest)
		return
	}
	var reqBody RequestBody
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	orgSetup.InvokeWithBody(w, reqBody)
}

// Handler for /client/query
func QueryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Parse query parameters
		chaincodeId := r.URL.Query().Get("chaincodeid")
		channelId := r.URL.Query().Get("channelid")
		function := r.URL.Query().Get("function")
		args := r.URL.Query()["args"]
		if chaincodeId == "" || channelId == "" || function == "" {
			http.Error(w, "Missing required query parameters", http.StatusBadRequest)
			return
		}
		session, _ := getSessionStore().Get(r, "fabric-session")
		orgSetup, ok := GetOrgSetup(session.ID)
		if !ok {
			http.Error(w, "Fabric client not initialized for this session. Call /client/ first.", http.StatusBadRequest)
			return
		}
		reqBody := RequestBody{
			ChaincodeId: chaincodeId,
			ChannelId:   channelId,
			Function:    function,
			Args:        args,
		}
		orgSetup.QueryWithBody(w, reqBody)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Handler for /client/ (initializes connection to Fabric blockchain)
func ClientHandler(w http.ResponseWriter, r *http.Request) {

	var clientRequestBody ClientRequestBody
	if err := json.NewDecoder(r.Body).Decode(&clientRequestBody); err != nil {
		http.Error(w, "Invalid OrgSetup: "+err.Error(), http.StatusBadRequest)
		return
	}
	session, _ := getSessionStore().Get(r, "fabric-session")
	if err := InitializeWithSession(clientRequestBody, session, w, r); err != nil {
		http.Error(w, "Error initializing org: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Fabric client connection initialized successfully."))
}

// Handler for /client/close
func CloseHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := getSessionStore().Get(r, "fabric-session")
	orgSetup, ok := GetOrgSetup(session.ID)
	if !ok {
		http.Error(w, "No active Fabric client connection for this session.", http.StatusBadRequest)
		return
	}
	err := orgSetup.Gateway.Close()
	if err != nil {
		http.Error(w, "Error closing Fabric client connection: "+err.Error(), http.StatusInternalServerError)
		return
	}
	RemoveOrgSetup(session.ID)
	session.Options.MaxAge = -1 // Invalidate session cookie
	session.Save(r, w)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Fabric client connection closed successfully."))
}
