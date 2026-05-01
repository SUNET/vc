package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"

	"github.com/SUNET/vc/pkg/vc20/credential"
	vc_ecdsa "github.com/SUNET/vc/pkg/vc20/crypto/ecdsa"
	vc_eddsa "github.com/SUNET/vc/pkg/vc20/crypto/eddsa"
)

var (
	port = flag.Int("port", 8888, "Port to listen on")
	key  *ecdsa.PrivateKey
)

func main() {
	flag.Parse()

	// Generate a key pair for the server
	var err error
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	log.Printf("Generated ECDSA P-256 key pair")

	http.HandleFunc("/credentials/issue", handleIssue)
	http.HandleFunc("/credentials/verify", handleVerify)
	http.HandleFunc("/presentations/verify", handleVerifyPresentation)
	http.HandleFunc("/stop", handleStop)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil { // #nosec G114
		log.Fatalf("Server failed: %v", err)
	}
}

type IssueRequest struct {
	Credential map[string]any `json:"credential"`
	Options    map[string]any `json:"options"`
}

type VerifyRequest struct {
	VerifiableCredential   map[string]any `json:"verifiableCredential"`
	VerifiablePresentation map[string]any `json:"verifiablePresentation"`
	Options                map[string]any `json:"options"`
}

type VerifyResponse struct {
	Verified bool     `json:"verified"`
	Errors   []string `json:"errors,omitempty"`
	Results  []any    `json:"results,omitempty"`
	Checks   []string `json:"checks,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func respondError(w http.ResponseWriter, message string, code int) {
	log.Printf("Error response (%d): %s", code, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message}) // #nosec G104
}

func respondVerify(w http.ResponseWriter, verified bool, errorMsg string) {
	if !verified {
		log.Printf("Verification failed: %s", errorMsg)
	} else {
		log.Printf("Verification successful")
	}
	resp := VerifyResponse{
		Verified: verified,
	}
	if errorMsg != "" {
		resp.Errors = []string{errorMsg}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) // #nosec G104
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	go func() {
		time.Sleep(100 * time.Millisecond)
		log.Fatal("Stopping server")
	}()
	w.Write([]byte("Stopping...")) // #nosec G104
}

func handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req IssueRequest
	if err := json.Unmarshal(body, &req); err != nil {
		respondError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Credential == nil {
		respondError(w, "credential is required", http.StatusBadRequest)
		return
	}

	if err := credential.ValidateCredential(req.Credential); err != nil {
		respondError(w, fmt.Sprintf("Invalid credential: %v", err), http.StatusBadRequest)
		return
	}

	// Determine cryptosuite
	cryptosuite := "ecdsa-rdfc-2019"
	if opts := req.Options; opts != nil {
		if cs, ok := opts["cryptosuite"].(string); ok {
			cryptosuite = cs
		}
	}

	// Marshal credential back to bytes for RDFCredential
	credBytes, err := json.Marshal(req.Credential)
	if err != nil {
		respondError(w, "Failed to marshal credential", http.StatusInternalServerError)
		return
	}

	cred, err := credential.NewRDFCredentialFromJSON(credBytes, nil)
	if err != nil {
		respondError(w, fmt.Sprintf("Failed to parse credential: %v", err), http.StatusBadRequest)
		return
	}

	var signedCred *credential.RDFCredential

	switch cryptosuite {
	case "ecdsa-rdfc-2019":
		suite := vc_ecdsa.NewSuite()
		opts := &vc_ecdsa.SignOptions{
			VerificationMethod: "did:example:issuer#key-1", // TODO: Make dynamic?
			ProofPurpose:       "assertionMethod",
			Created:            time.Now().UTC(),
		}
		signedCred, err = suite.Sign(r.Context(), cred, key, opts)
	case "ecdsa-sd-2023":
		suite := vc_ecdsa.NewSdSuite()
		opts := &vc_ecdsa.SdSignOptions{
			VerificationMethod: "did:example:issuer#key-1",
			ProofPurpose:       "assertionMethod",
			Created:            time.Now().UTC(),
			// MandatoryPointers: ... // TODO: Support mandatory pointers from request
		}
		signedCred, err = suite.Sign(cred, key, opts)
	default:
		respondError(w, fmt.Sprintf("Unsupported cryptosuite: %s", cryptosuite), http.StatusBadRequest)
		return
	}

	if err != nil {
		respondError(w, fmt.Sprintf("Failed to sign: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the original JSON which preserves context and structure
	signedJSON := []byte(signedCred.OriginalJSON())
	if len(signedJSON) == 0 {
		// Fallback if original JSON is missing (should not happen with current Sign implementation)
		signedJSON, err = signedCred.ToJSON()
		if err != nil {
			respondError(w, "Failed to serialize signed credential", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(signedJSON) // #nosec G104
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req VerifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		respondError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.VerifiableCredential == nil {
		respondError(w, "verifiableCredential is required", http.StatusBadRequest)
		return
	}

	if err := credential.ValidateCredential(req.VerifiableCredential); err != nil {
		respondError(w, fmt.Sprintf("Invalid credential: %v", err), http.StatusBadRequest)
		return
	}

	credBytes, err := json.Marshal(req.VerifiableCredential)
	if err != nil {
		respondError(w, "Failed to marshal credential", http.StatusInternalServerError)
		return
	}

	cred, err := credential.NewRDFCredentialFromJSON(credBytes, nil)
	if err != nil {
		respondVerify(w, false, fmt.Sprintf("Failed to parse credential: %v", err))
		return
	}

	// Detect suite from proof
	// We need to look at the proof object in the credential
	// RDFCredential has GetProofObject but that returns RDF.
	// We can check the JSON map directly.
	proof, ok := req.VerifiableCredential["proof"].(map[string]any)
	if !ok {
		// Could be array
		if proofs, ok := req.VerifiableCredential["proof"].([]any); ok && len(proofs) > 0 {
			if p, ok := proofs[0].(map[string]any); ok {
				proof = p
			}
		}
	}

	if proof == nil {
		respondVerify(w, false, "No proof found")
		return
	}

	cryptosuite, _ := proof["cryptosuite"].(string)
	// If not in cryptosuite field, check type?
	// ecdsa-rdfc-2019 uses type DataIntegrityProof and cryptosuite property.

	var verifyErr error
	switch cryptosuite {
	case "ecdsa-rdfc-2019":
		suite := vc_ecdsa.NewSuite()
		verifyErr = suite.Verify(cred, &key.PublicKey)
	case "ecdsa-sd-2023":
		suite := vc_ecdsa.NewSdSuite()
		verifyErr = suite.Verify(cred, &key.PublicKey)
	default:
		verifyErr = fmt.Errorf("unsupported cryptosuite: %s", cryptosuite)
	}

	if verifyErr != nil {
		respondVerify(w, false, verifyErr.Error())
	} else {
		respondVerify(w, true, "")
	}
}

func handleVerifyPresentation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	log.Printf("VerifyPresentation Request Body: %s", string(body))

	var req VerifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		respondError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.VerifiablePresentation == nil {
		// Check if the body itself is the VP (some tests might do this)
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err == nil {
			if _, ok := raw["type"]; ok {
				req.VerifiablePresentation = raw
			}
		}
	}

	if req.VerifiablePresentation == nil {
		respondError(w, "verifiablePresentation is required", http.StatusBadRequest)
		return
	}

	if err := credential.ValidatePresentation(req.VerifiablePresentation); err != nil {
		respondError(w, fmt.Sprintf("Invalid presentation: %v", err), http.StatusBadRequest)
		return
	}

	// Verify JSON-LD contexts by attempting expansion
	proc := ld.NewJsonLdProcessor()
	opts := ld.NewJsonLdOptions("")
	opts.DocumentLoader = credential.GetGlobalLoader()

	_, err = proc.Expand(req.VerifiablePresentation, opts)
	if err != nil {
		respondError(w, fmt.Sprintf("Invalid presentation context: %v", err), http.StatusBadRequest)
		return
	}

	// Extract proof
	var proof map[string]any
	if p, ok := req.VerifiablePresentation["proof"].(map[string]any); ok {
		proof = p
	} else if proofs, ok := req.VerifiablePresentation["proof"].([]any); ok && len(proofs) > 0 {
		if p, ok := proofs[0].(map[string]any); ok {
			proof = p
		}
	}

	if proof == nil {
		respondVerify(w, false, "No proof found")
		return
	}

	cryptosuite, _ := proof["cryptosuite"].(string)

	// Create RDFCredential from VP
	vpBytes, err := json.Marshal(req.VerifiablePresentation)
	if err != nil {
		respondError(w, "Failed to marshal VP", http.StatusInternalServerError)
		return
	}

	vpCred, err := credential.NewRDFCredentialFromJSON(vpBytes, nil)
	if err != nil {
		respondVerify(w, false, fmt.Sprintf("Failed to parse VP: %v", err))
		return
	}

	var verifyErr error
	switch cryptosuite {
	case "eddsa-rdfc-2022":
		verifyErr = verifyEdDSA(vpCred, proof)
	default:
		verifyErr = fmt.Errorf("unsupported cryptosuite: %s", cryptosuite)
	}

	if verifyErr != nil {
		respondVerify(w, false, verifyErr.Error())
	} else {
		respondVerify(w, true, "")
	}
}

func verifyEdDSA(vpCred *credential.RDFCredential, proof map[string]any) error {
	// 1. Get verificationMethod
	vm, ok := proof["verificationMethod"].(string)
	if !ok {
		return fmt.Errorf("missing verificationMethod")
	}

	// 2. Resolve key from DID
	// We only support did:key for now
	if !strings.HasPrefix(vm, "did:key:") {
		return fmt.Errorf("unsupported verificationMethod: %s", vm)
	}

	// Extract multibase key
	// did:key:z6Mk...#...
	parts := strings.Split(vm, "#")
	didKey := parts[0]
	mbKey := strings.TrimPrefix(didKey, "did:key:")

	// Decode multibase
	_, decoded, err := multibase.Decode(mbKey)
	if err != nil {
		return fmt.Errorf("failed to decode did:key: %v", err)
	}

	// Check multicodec prefix
	// Ed25519 public key is 0xed 0x01 (2 bytes)
	if len(decoded) != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return fmt.Errorf("unsupported key type or invalid length")
	}

	pubKey := ed25519.PublicKey(decoded[2:])

	// 3. Verify using suite
	suite := vc_eddsa.NewSuite()
	return suite.Verify(vpCred, pubKey)
}
