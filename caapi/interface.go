package caapi

// CAConfig contains configuration for connecting to Fabric CA
type CAConfig struct {
	CAURL    string `json:"caUrl"`    // CA server URL
	CAName   string `json:"caName"`   // CA name
	MSPID    string `json:"mspId"`    // MSP ID
	TLSCerts string `json:"tlsCerts"` // Path to TLS certificates (optional)
	SkipTLS  bool   `json:"skipTls"`  // Skip TLS verification for development
}

// EnrollmentRequest represents a request to enroll a new identity
type EnrollmentRequest struct {
	CAConfig     CAConfig `json:"caConfig"`
	EnrollmentID string   `json:"enrollmentId"` // User ID to enroll
	Secret       string   `json:"secret"`       // Enrollment secret
	Profile      string   `json:"profile"`      // Certificate profile (optional)
	CSRInfo      CSRInfo  `json:"csrInfo"`      // Certificate signing request info
}

// CSRInfo contains certificate signing request information
type CSRInfo struct {
	CN    string   `json:"cn"`    // Common Name
	Names []Name   `json:"names"` // Subject names
	Hosts []string `json:"hosts"` // Subject Alternative Names
}

// Name represents a subject name
type Name struct {
	C  string `json:"C"`  // Country
	ST string `json:"ST"` // State
	L  string `json:"L"`  // Locality
	O  string `json:"O"`  // Organization
	OU string `json:"OU"` // Organizational Unit
}

// RegistrationRequest represents a request to register a new identity
type RegistrationRequest struct {
	CAConfig       CAConfig      `json:"caConfig"`
	AdminIdentity  AdminIdentity `json:"adminIdentity"`  // Admin credentials
	RegistrationID string        `json:"registrationId"` // New user ID
	Secret         string        `json:"secret"`         // Optional secret (auto-generated if empty)
	Type           string        `json:"type"`           // Identity type (client, peer, orderer, admin)
	Affiliation    string        `json:"affiliation"`    // User affiliation
	Attributes     []Attribute   `json:"attributes"`     // Additional attributes
}

// Attribute represents a user attribute
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AdminIdentity contains admin credentials for registration operations
type AdminIdentity struct {
	EnrollmentID string `json:"enrollmentId"`
	Secret       string `json:"secret"`
}

// CAInfoResponse represents the response from CA info endpoint
type CAInfoResponse struct {
	Success bool   `json:"success"`
	Result  CAInfo `json:"result"`
}

// CAInfo contains CA server information
type CAInfo struct {
	CAName                    string `json:"CAName"`
	CAChain                   string `json:"CAChain"`
	IssuerPublicKey           string `json:"IssuerPublicKey"`
	IssuerRevocationPublicKey string `json:"IssuerRevocationPublicKey"`
	Version                   string `json:"Version"`
}
