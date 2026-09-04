package openid4vp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/SUNET/vc/pkg/openid4vp"
)

// Example_combinedPresentation_universityAdmission demonstrates a university
// admissions use case where the Verifier requests a PID (identity) and a
// diploma attestation, then verifies they belong to the same applicant.
//
// ARF 3.0 Discussion Topic K §3.1 lists this as a core combined presentation
// scenario: a university needs citizenship (PID) plus academic credentials
// (diploma) and must confirm both originate from the same person.
func Example_combinedPresentation_universityAdmission() {
	// ── Verifier setup ──────────────────────────────────────────────────
	// The verifier is configured to:
	//   1. Compare holder keys (high confidence — same WSCD)
	//   2. Compare family_name + birth_date across credentials (medium confidence)
	//   3. Enforce binding — reject if not established
	verifier := &openid4vp.CombinedBindingVerifier{
		Config: openid4vp.CombinedPresentationConfig{
			Enabled:           true,
			Enforcement:       openid4vp.BindingEnforcementEnforce,
			KeyBindingEnabled: true,
			BindingAttributes: []openid4vp.BindingAttributeConfig{
				{Paths: []string{"family_name", "birth_date"}}, // compound: both must match
			},
		},
	}

	// ── Simulate wallet response ────────────────────────────────────────
	// In production, these are extracted during VerificationDirectPost
	// after SD-JWT/mDoc verification. Here we simulate two credentials
	// that share the same holder key (same wallet/WSCD).

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	thumbprint, err := openid4vp.ECPublicKeyToJWKThumbprint(&holderKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	credentials := []openid4vp.VerifiedCredentialBinding{
		{
			Scope:               "pid",
			HolderKeyThumbprint: thumbprint,
			Claims: map[string]any{
				"given_name":  "Anna",
				"family_name": "Lindqvist",
				"birth_date":  "1998-03-15",
				"nationality": "SE",
				"sub":         "urn:eudi:pid:se:199803150123",
			},
		},
		{
			Scope:               "diploma",
			HolderKeyThumbprint: thumbprint, // same key → same WSCD → high confidence
			Claims: map[string]any{
				"given_name":        "Anna",
				"family_name":       "Lindqvist",
				"birth_date":        "1998-03-15",
				"degree":            "MSc Computer Science",
				"issuing_authority": "Uppsala University",
			},
		},
	}

	// ── Verify binding ──────────────────────────────────────────────────
	result, err := verifier.Verify(credentials)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Bound: %v\n", result.Bound)
	fmt.Printf("Confidence: %s\n", result.HighestConfidence)
	for _, r := range result.Results {
		fmt.Printf("  [%s] confidence=%s\n", r.Method, r.Confidence)
	}

	// Output:
	// Bound: true
	// Confidence: high
	//   [session_based] confidence=low
	//   [key_based] confidence=high
	//   [attribute_based] confidence=medium
}

// Example_combinedPresentation_differentHolderKeys shows how enforcement
// catches a presentation where credentials are bound to different keys,
// indicating they may belong to different users.
func Example_combinedPresentation_differentHolderKeys() {
	verifier := &openid4vp.CombinedBindingVerifier{
		Config: openid4vp.CombinedPresentationConfig{
			Enabled:           true,
			Enforcement:       openid4vp.BindingEnforcementEnforce,
			KeyBindingEnabled: true,
		},
	}

	// Two different holder keys → different WSCDs → suspicious
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thumb1, _ := openid4vp.ECPublicKeyToJWKThumbprint(&key1.PublicKey)
	thumb2, _ := openid4vp.ECPublicKeyToJWKThumbprint(&key2.PublicKey)

	credentials := []openid4vp.VerifiedCredentialBinding{
		{Scope: "pid", HolderKeyThumbprint: thumb1, Claims: map[string]any{"sub": "user-A"}},
		{Scope: "ehic", HolderKeyThumbprint: thumb2, Claims: map[string]any{"sub": "user-B"}},
	}

	result, _ := verifier.Verify(credentials)

	fmt.Printf("Bound: %v\n", result.Bound)
	fmt.Printf("Confidence: %s\n", result.HighestConfidence)
	for _, r := range result.Results {
		if r.Error != "" {
			fmt.Printf("  [%s] ERROR: %s\n", r.Method, r.Error)
		}
	}

	// Output:
	// Bound: false
	// Confidence: low
	//   [key_based] ERROR: holder key mismatch: credentials are bound to different keys
}

// Example_combinedPresentation_warnMode shows how "warn" enforcement allows
// the presentation through even when key binding fails, relying on session-based
// trust. This follows ARF 3.0 ACP_08: "SHOULD NOT refuse solely because proof
// is absent."
func Example_combinedPresentation_warnMode() {
	verifier := &openid4vp.CombinedBindingVerifier{
		Config: openid4vp.CombinedPresentationConfig{
			Enabled:           true,
			Enforcement:       openid4vp.BindingEnforcementWarn,
			KeyBindingEnabled: true,
			BindingAttributes: []openid4vp.BindingAttributeConfig{
				{Paths: []string{"sub"}},
			},
		},
	}

	// Credentials lack key material but share "sub" identifier
	credentials := []openid4vp.VerifiedCredentialBinding{
		{Scope: "pid", Claims: map[string]any{"sub": "urn:eudi:pid:se:199803150123"}},
		{Scope: "ehic", Claims: map[string]any{"sub": "urn:eudi:pid:se:199803150123"}},
	}

	result, _ := verifier.Verify(credentials)

	fmt.Printf("Bound: %v\n", result.Bound)
	fmt.Printf("Confidence: %s\n", result.HighestConfidence)

	// Output:
	// Bound: true
	// Confidence: medium
}

func encodeBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
