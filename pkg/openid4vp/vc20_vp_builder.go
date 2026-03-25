package openid4vp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
	ecdsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/ecdsa"
	eddsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/eddsa"
)

// VPBuilder builds W3C Verifiable Presentations for OpenID4VP flows.
type VPBuilder struct {
	holderDID          string
	defaultCryptosuite string
}

// VPBuilderOption configures a VPBuilder.
type VPBuilderOption func(*VPBuilder)

// WithHolderDID sets the holder DID for presentations.
func WithHolderDID(did string) VPBuilderOption {
	return func(b *VPBuilder) {
		b.holderDID = did
	}
}

// WithDefaultCryptosuite sets the default cryptosuite for VP signing.
func WithDefaultCryptosuite(suite string) VPBuilderOption {
	return func(b *VPBuilder) {
		b.defaultCryptosuite = suite
	}
}

// NewVPBuilder creates a new VPBuilder with the given options.
func NewVPBuilder(opts ...VPBuilderOption) *VPBuilder {
	b := &VPBuilder{
		defaultCryptosuite: CryptosuiteECDSA2019, // Default to ecdsa-rdfc-2019
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// VPBuildOptions contains options for building a Verifiable Presentation.
type VPBuildOptions struct {
	// HolderDID is the DID of the presentation holder
	HolderDID string

	// VerificationMethod is the full verification method URI (e.g., did:key:z6Mk...#key-1)
	VerificationMethod string

	// Nonce is the challenge/nonce from the verifier (required for OpenID4VP)
	Nonce string

	// Domain is the audience/domain for the presentation
	Domain string

	// Cryptosuite specifies which cryptosuite to use for signing
	// Supported: "ecdsa-rdfc-2019", "eddsa-rdfc-2022"
	Cryptosuite string

	// Created timestamp for the proof (defaults to now)
	Created time.Time
}

// BuildVC20Presentation creates a signed W3C Verifiable Presentation.
// The credentials parameter should be JSON bytes of W3C VC 2.0 credentials.
// The privateKey should match the cryptosuite (ed25519.PrivateKey for EdDSA, *ecdsa.PrivateKey for ECDSA).
func (b *VPBuilder) BuildVC20Presentation(
	credentials [][]byte,
	privateKey crypto.PrivateKey,
	opts *VPBuildOptions,
) ([]byte, error) {
	if len(credentials) == 0 {
		return nil, fmt.Errorf("no credentials provided")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if opts == nil {
		return nil, fmt.Errorf("build options are nil")
	}

	// Use default values where needed
	holderDID := opts.HolderDID
	if holderDID == "" {
		holderDID = b.holderDID
	}
	if holderDID == "" {
		return nil, fmt.Errorf("holder DID is required")
	}

	cryptosuite := opts.Cryptosuite
	if cryptosuite == "" {
		cryptosuite = b.defaultCryptosuite
	}

	verificationMethod := opts.VerificationMethod
	if verificationMethod == "" {
		// Default to holder DID with #key-1 fragment
		verificationMethod = holderDID + "#key-1"
	}

	// 1. Parse credentials
	parsedCredentials := make([]any, 0, len(credentials))
	for i, credBytes := range credentials {
		var cred any
		if err := json.Unmarshal(credBytes, &cred); err != nil {
			return nil, fmt.Errorf("failed to parse credential %d: %w", i, err)
		}
		parsedCredentials = append(parsedCredentials, cred)
	}

	// 2. Build VP structure
	// W3C VC 2.0 context includes data integrity proofs
	vpMap := map[string]any{
		"@context": []string{
			credential.ContextV2,
		},
		"type":                 []string{"VerifiablePresentation"},
		"holder":               holderDID,
		"verifiableCredential": parsedCredentials,
	}

	// 3. Add VP ID if not provided
	vpMap["id"] = fmt.Sprintf("urn:uuid:%s", generateUUID())

	// 4. Serialize VP without proof
	vpBytes, err := json.Marshal(vpMap)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VP: %w", err)
	}

	// 5. Sign the VP based on cryptosuite
	var signedVPBytes []byte
	switch cryptosuite {
	case CryptosuiteEdDSA2022:
		signedVPBytes, err = b.signWithEdDSA(vpBytes, privateKey, verificationMethod, opts)
	case CryptosuiteECDSA2019:
		signedVPBytes, err = b.signWithECDSA(vpBytes, privateKey, verificationMethod, opts)
	default:
		return nil, fmt.Errorf("unsupported cryptosuite for VP signing: %s", cryptosuite)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign VP with %s: %w", cryptosuite, err)
	}

	return signedVPBytes, nil
}

// signWithEdDSA signs the VP using eddsa-rdfc-2022.
func (b *VPBuilder) signWithEdDSA(vpBytes []byte, privateKey crypto.PrivateKey, verificationMethod string, opts *VPBuildOptions) ([]byte, error) {
	edKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ed25519.PrivateKey")
	}

	// Parse VP as RDF credential
	ldOpts := credential.NewJSONLDOptions("")
	vpCred, err := credential.NewRDFCredentialFromJSON(vpBytes, ldOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VP as RDF: %w", err)
	}

	// Create sign options
	signOpts := &eddsaSuite.SignOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "authentication",
		Created:            opts.Created,
		Domain:             opts.Domain,
		Challenge:          opts.Nonce,
	}

	if signOpts.Created.IsZero() {
		signOpts.Created = time.Now().UTC()
	}

	// Sign
	suite := eddsaSuite.NewSuite()
	signedVP, err := suite.Sign(vpCred, edKey, signOpts)
	if err != nil {
		return nil, fmt.Errorf("EdDSA signing failed: %w", err)
	}

	return signedVP.ToCompactJSON()
}

// signWithECDSA signs the VP using ecdsa-rdfc-2019.
func (b *VPBuilder) signWithECDSA(vpBytes []byte, privateKey crypto.PrivateKey, verificationMethod string, opts *VPBuildOptions) ([]byte, error) {
	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not *ecdsa.PrivateKey")
	}

	// Parse VP as RDF credential
	ldOpts := credential.NewJSONLDOptions("")
	vpCred, err := credential.NewRDFCredentialFromJSON(vpBytes, ldOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VP as RDF: %w", err)
	}

	// Create sign options
	signOpts := &ecdsaSuite.SignOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "authentication",
		Created:            opts.Created,
		Domain:             opts.Domain,
		Challenge:          opts.Nonce,
	}

	if signOpts.Created.IsZero() {
		signOpts.Created = time.Now().UTC()
	}

	// Sign
	suite := ecdsaSuite.NewSuite()
	signedVP, err := suite.Sign(context.Background(), vpCred, ecKey, signOpts)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	return signedVP.ToCompactJSON()
}
