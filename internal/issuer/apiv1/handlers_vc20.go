package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/vc20/contextstore"
	"github.com/SUNET/vc/pkg/vc20/credential"
	ecdsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/ecdsa"
	eddsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/eddsa"

	"github.com/google/uuid"
)

// CreateVC20Request is the request for W3C VC 2.0 issuance
type CreateVC20Request struct {
	DocumentData      []byte   `json:"document_data" validate:"required"`
	Scope             string   `json:"scope" validate:"required"`
	CredentialTypes   []string `json:"credential_types" validate:"required"`
	SubjectDID        string   `json:"subject_did,omitempty"`
	Cryptosuite       string   `json:"cryptosuite"`
	MandatoryPointers []string `json:"mandatory_pointers,omitempty"`
}

// CreateVC20Reply is the reply for W3C VC 2.0 issuance
type CreateVC20Reply struct {
	Credential        []byte `json:"credential"`
	CredentialID      string `json:"credential_id"`
	StatusListSection int64  `json:"status_list_section"`
	StatusListIndex   int64  `json:"status_list_index"`
	// StatusListURI is the list the entry was allocated in. Empty when no
	// status entry was allocated, i.e. the credential is not revocable.
	StatusListURI string `json:"status_list_uri,omitempty"`
	// StatusListBackend names the backend that issued the entry; see
	// CreateCredentialReply.TokenStatusListBackend.
	StatusListBackend string `json:"status_list_backend,omitempty"`
	ValidFrom         string `json:"valid_from"`
	ValidUntil        string `json:"valid_until,omitempty"`
}

// MakeVC20 creates a W3C VC 2.0 Data Integrity credential
func (c *Client) MakeVC20(ctx context.Context, req *CreateVC20Request) (*CreateVC20Reply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:MakeVC20")
	defer span.End()

	c.log.Debug("MakeVC20", "scope", req.Scope, "cryptosuite", req.Cryptosuite, "types", req.CredentialTypes)

	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		c.log.Debug("Validation", "err", err)
		return nil, err
	}

	// Default cryptosuite if not specified
	cryptosuite := req.Cryptosuite
	if cryptosuite == "" {
		cryptosuite = openid4vp.CryptosuiteECDSA2019
	}

	// Validate cryptosuite
	if !isValidCryptosuite(cryptosuite) {
		return nil, fmt.Errorf("unsupported cryptosuite: %s", cryptosuite)
	}

	// Use credential types from request (required field)
	credentialTypes := req.CredentialTypes
	if len(credentialTypes) == 0 {
		credentialTypes = []string{"VerifiableCredential"}
	}

	// Parse document data into credential subject
	var credentialSubject map[string]any
	if err := json.Unmarshal(req.DocumentData, &credentialSubject); err != nil {
		c.log.Error(err, "failed to parse document data")
		return nil, fmt.Errorf("failed to parse document data: %w", err)
	}

	// Add subject DID if provided
	if req.SubjectDID != "" {
		credentialSubject["id"] = req.SubjectDID
	}

	// Generate credential ID
	credentialID := fmt.Sprintf("urn:uuid:%s", uuid.New().String())

	// Set timestamps
	validFrom := time.Now().UTC()
	var validUntil *time.Time

	// Default validity: 1 year from now
	defaultExpiry := validFrom.AddDate(1, 0, 0)
	validUntil = &defaultExpiry

	// Allocate a status list entry for revocation support, if any allocator
	// is configured. Best-effort for the registry backend, matching this
	// path's pre-existing behaviour - VC 2.0 issuance has never required a
	// status entry - but an external service's degraded_mode is honoured.
	// See allocateOptionalStatus.
	var statusSection, statusIndex int64
	var statusURI, statusBackend string
	// No allocation when the credential will carry no status. Allocating
	// anyway consumed a slot per issuance and handed the APIGW an entry to
	// record a revocation mapping for a credential with nothing to revoke -
	// and made degraded_mode "fail" block a format that is deliberately
	// non-revocable in this configuration.
	statusAlloc, err := c.allocateVC20Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate status list entry: %w", err)
	}
	if statusAlloc != nil {
		statusSection, statusIndex, statusURI, statusBackend = statusAlloc.Section, statusAlloc.Index, statusAlloc.URI, statusAlloc.Backend
		c.log.Debug("status list entry allocated for vc20", "section", statusSection, "index", statusIndex, "uri", statusURI)
	}

	// Build the credential JSON structure
	credentialJSON, err := c.buildVC20CredentialJSON(
		credentialID,
		credentialTypes,
		credentialSubject,
		validFrom,
		validUntil,
		statusAlloc,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build credential JSON: %w", err)
	}

	// Parse into RDFCredential
	cred, err := credential.NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	// Sign the credential
	signedCred, err := c.signVC20Credential(ctx, cred, cryptosuite, req.MandatoryPointers)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %w", err)
	}

	// Get signed credential JSON
	signedJSON, err := signedCred.ToCompactJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed credential: %w", err)
	}

	reply := &CreateVC20Reply{
		Credential:        signedJSON,
		CredentialID:      credentialID,
		StatusListSection: statusSection,
		StatusListIndex:   statusIndex,
		StatusListURI:     statusURI,
		StatusListBackend: statusBackend,
		ValidFrom:         validFrom.Format(time.RFC3339),
	}

	if validUntil != nil {
		reply.ValidUntil = validUntil.Format(time.RFC3339)
	}

	return reply, nil
}

// buildVC20CredentialJSON builds the JSON-LD credential structure
func (c *Client) buildVC20CredentialJSON(
	credentialID string,
	types []string,
	credentialSubject map[string]any,
	validFrom time.Time,
	validUntil *time.Time,
	status *statusAllocation,
) ([]byte, error) {
	// Ensure VerifiableCredential is in types
	hasVC := slices.Contains(types, "VerifiableCredential")
	if !hasVC {
		types = append([]string{"VerifiableCredential"}, types...)
	}

	cred := map[string]any{
		"@context":          []string{credential.ContextV2},
		"id":                credentialID,
		"type":              types,
		"issuer":            c.cfg.Issuer.JWTAttribute.Issuer,
		"validFrom":         validFrom.Format(time.RFC3339),
		"credentialSubject": credentialSubject,
	}

	if validUntil != nil {
		cred["validUntil"] = validUntil.Format(time.RFC3339)
	}

	// credentialStatus, when an entry was allocated. The context that
	// defines TokenStatusListEntry has to be added alongside it: vc signs
	// VC 2.0 with Data Integrity over canonicalized RDF, and terms no
	// context defines expand to relative IRIs and vanish from the canonical
	// form - the status would then not be covered by the proof at all, so a
	// verifier could have it stripped or rewritten without the signature
	// failing. Adding the context only when there is a status keeps it out
	// of credentials that have none.
	if status != nil {
		cred["@context"] = []string{credential.ContextV2, contextstore.TokenStatusListContextURL}
		cred["credentialStatus"] = map[string]any{
			// The entry identifies itself by the list it is in and its
			// place in that list, which is exactly what a verifier needs
			// to resolve it and what the other formats carry as
			// status_list.{uri,idx}.
			"id":              fmt.Sprintf("%s#%d", status.URI, status.Index),
			"type":            contextstore.TokenStatusListEntryType,
			"statusListUri":   status.URI,
			"statusListIndex": strconv.FormatInt(status.Index, 10),
			"statusPurpose":   "revocation",
		}
	}

	return json.Marshal(cred)
}

// signVC20Credential signs a credential using the specified cryptosuite
func (c *Client) signVC20Credential(ctx context.Context, cred *credential.RDFCredential, cryptosuite string, mandatoryPointers []string) (*credential.RDFCredential, error) {
	verificationMethod := c.cfg.Issuer.JWTAttribute.Issuer + "#key-1"
	if kid := c.signer.KeyID(); kid != "" {
		verificationMethod = c.cfg.Issuer.JWTAttribute.Issuer + "#" + kid
	}

	switch cryptosuite {
	case openid4vp.CryptosuiteECDSA2019:
		key, ok := c.privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ecdsa-rdfc-2019 requires ECDSA private key, got %T", c.privateKey)
		}
		suite := ecdsaSuite.NewSuite()
		return suite.Sign(ctx, cred, key, &ecdsaSuite.SignOptions{
			VerificationMethod: verificationMethod,
			ProofPurpose:       "assertionMethod",
			Created:            time.Now().UTC(),
		})

	case openid4vp.CryptosuiteECDSASd:
		key, ok := c.privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ecdsa-sd-2023 requires ECDSA private key, got %T", c.privateKey)
		}
		sdSuite := ecdsaSuite.NewSdSuite()
		return sdSuite.Sign(cred, key, &ecdsaSuite.SdSignOptions{
			VerificationMethod: verificationMethod,
			ProofPurpose:       "assertionMethod",
			Created:            time.Now().UTC(),
			MandatoryPointers:  mandatoryPointers,
		})

	case openid4vp.CryptosuiteEdDSA2022:
		key, ok := c.privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("eddsa-rdfc-2022 requires Ed25519 private key, got %T", c.privateKey)
		}
		suite := eddsaSuite.NewSuite()
		return suite.Sign(cred, key, &eddsaSuite.SignOptions{
			VerificationMethod: verificationMethod,
			ProofPurpose:       "assertionMethod",
			Created:            time.Now().UTC(),
		})

	default:
		return nil, fmt.Errorf("unsupported cryptosuite: %s", cryptosuite)
	}
}

// isValidCryptosuite checks if the cryptosuite is supported
func isValidCryptosuite(cryptosuite string) bool {
	switch cryptosuite {
	case openid4vp.CryptosuiteECDSA2019, openid4vp.CryptosuiteECDSASd, openid4vp.CryptosuiteEdDSA2022:
		return true
	default:
		return false
	}
}

// vc20StatusEnabled reports whether issued VC 2.0 credentials should carry
// a credentialStatus entry.
//
// Off unless issuer.vc20_status_enable is explicitly true. See that field
// for why: the context namespace is a placeholder no third party can
// resolve, and no verifier checks the result yet, so a credential emitted
// with one would look revocable without being so.
func (c *Client) vc20StatusEnabled() bool {
	if c.cfg == nil || c.cfg.Issuer == nil || c.cfg.Issuer.VC20StatusEnable == nil {
		return false
	}
	return *c.cfg.Issuer.VC20StatusEnable
}

// allocateVC20Status allocates a status-list entry for a VC 2.0 issuance,
// or nothing when the credential will not carry a status.
//
// Separate from the caller so the gate is testable on its own: allocating
// for a credential that will carry no status reference consumes a slot per
// issuance, hands the APIGW an entry to record a mapping nothing can use,
// and makes degraded_mode "fail" block a format that is deliberately
// non-revocable in this configuration.
func (c *Client) allocateVC20Status(ctx context.Context) (*statusAllocation, error) {
	if !c.vc20StatusEnabled() {
		return nil, nil
	}
	return c.allocateOptionalStatus(ctx, "vc20")
}
