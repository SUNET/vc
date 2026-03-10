//go:build vc20
// +build vc20

package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/helpers"
	"vc/pkg/openid4vp"
	"vc/pkg/vc20/credential"
	ecdsaSuite "vc/pkg/vc20/crypto/ecdsa"
	eddsaSuite "vc/pkg/vc20/crypto/eddsa"

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

	// Allocate status list entry for revocation support (if registry is configured)
	var statusSection, statusIndex int64
	if c.registryClient != nil {
		grpcReply, err := c.registryClient.TokenStatusListAddStatus(ctx, &apiv1_registry.TokenStatusListAddStatusRequest{
			Status: 0, // VALID status for new credential
		})
		if err != nil {
			c.log.Info("failed to allocate status list entry, issuing without revocation support", "error", err)
		} else {
			statusSection = grpcReply.GetSection()
			statusIndex = grpcReply.GetIndex()
			c.log.Debug("status list entry allocated for vc20", "section", statusSection, "index", statusIndex)
		}
	}

	// Build the credential JSON structure
	credentialJSON, err := c.buildVC20CredentialJSON(
		credentialID,
		credentialTypes,
		credentialSubject,
		validFrom,
		validUntil,
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
) ([]byte, error) {
	// Ensure VerifiableCredential is in types
	hasVC := false
	for _, t := range types {
		if t == "VerifiableCredential" {
			hasVC = true
			break
		}
	}
	if !hasVC {
		types = append([]string{"VerifiableCredential"}, types...)
	}

	cred := map[string]any{
		"@context":          []string{"https://www.w3.org/ns/credentials/v2"},
		"id":                credentialID,
		"type":              types,
		"issuer":            c.cfg.Issuer.JWTAttribute.Issuer,
		"validFrom":         validFrom.Format(time.RFC3339),
		"credentialSubject": credentialSubject,
	}

	if validUntil != nil {
		cred["validUntil"] = validUntil.Format(time.RFC3339)
	}

	return json.Marshal(cred)
}

// signVC20Credential signs a credential using the specified cryptosuite
func (c *Client) signVC20Credential(ctx context.Context, cred *credential.RDFCredential, cryptosuite string, mandatoryPointers []string) (*credential.RDFCredential, error) {
	// Get the verification method from config, using signer's KeyID for consistency
	kid := c.signer.KeyID()
	verificationMethod := c.cfg.Issuer.JWTAttribute.Issuer + "#key-1"
	if kid != "" {
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
