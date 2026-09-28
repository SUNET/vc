package credential

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/vc20/contextstore"
)

// buildCredentialWithStatus mirrors what the issuer emits for a VC 2.0
// credential that has a Token Status List entry.
func buildCredentialWithStatus(t *testing.T, contexts []string) []byte {
	t.Helper()
	cred := map[string]any{
		"@context":  contexts,
		"id":        "urn:uuid:11111111-2222-3333-4444-555555555555",
		"type":      []string{"VerifiableCredential"},
		"issuer":    "https://issuer.example.com",
		"validFrom": "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{
			"id": "did:example:holder",
		},
		"credentialStatus": map[string]any{
			"id":              "https://status.example.com/statuslists/7#42",
			"type":            contextstore.TokenStatusListEntryType,
			"statusListUri":   "https://status.example.com/statuslists/7",
			"statusListIndex": "42",
			"statusPurpose":   "revocation",
		},
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestCredentialStatusIsCoveredByCanonicalForm is the reason the Token
// Status List context is bundled at all.
//
// vc signs VC 2.0 with Data Integrity, which signs the CANONICALIZED RDF,
// not the JSON. A term no context defines expands to a relative IRI and is
// dropped from the canonical form - so a credentialStatus written with
// undefined terms is not covered by the proof, and can be stripped or
// rewritten without the signature failing. The only way to see that is to
// canonicalize and look for the triples.
func TestCredentialStatusIsCoveredByCanonicalForm(t *testing.T) {
	raw := buildCredentialWithStatus(t, []string{ContextV2, contextstore.TokenStatusListContextURL})

	cred, err := NewRDFCredentialFromJSON(raw, nil)
	if err != nil {
		t.Fatalf("NewRDFCredentialFromJSON: %v", err)
	}

	canonical, err := cred.CanonicalForm()
	if err != nil {
		t.Fatalf("CanonicalForm: %v", err)
	}

	// The predicates must be ABSOLUTE IRIs under the Token Status List
	// namespace. A term the context failed to define would appear as a
	// relative IRI (<statusListUri>) or not at all.
	for _, want := range []string{
		"<https://ns.invalid/vc/token-status-list#statusListUri> <https://status.example.com/statuslists/7>",
		`<https://ns.invalid/vc/token-status-list#statusListIndex> "42"`,
		"<https://ns.invalid/vc/token-status-list#TokenStatusListEntry>",
		"credentials#credentialStatus",
	} {
		if !strings.Contains(canonical, want) {
			t.Fatalf("canonical form is missing %q, so the proof would not cover the credential's status.\n--- canonical form ---\n%s", want, canonical)
		}
	}

	// A relative IRI means a term the context did not define. #685's
	// validator refuses those on the credential side, so one here would
	// make the credential unverifiable as well as unsigned-over.
	for _, bad := range []string{"<TokenStatusListEntry>", "<statusListUri>", "<statusListIndex>"} {
		if strings.Contains(canonical, bad) {
			t.Fatalf("canonical form contains the relative IRI %q - the context did not define that term.\n--- canonical form ---\n%s", bad, canonical)
		}
	}
}

// TestCredentialStatusVanishesWithoutItsContext proves the failure mode the
// test above guards against is real, and is exactly why the context must be
// added to @context alongside the credentialStatus. Same credential, same
// terms, only the context omitted: the status silently disappears from what
// gets signed.
func TestCredentialStatusVanishesWithoutItsContext(t *testing.T) {
	raw := buildCredentialWithStatus(t, []string{ContextV2})

	cred, err := NewRDFCredentialFromJSON(raw, nil)
	if err != nil {
		// Refusing outright is also an acceptable outcome - what must not
		// happen is silently signing a credential whose status was dropped.
		return
	}
	canonical, err := cred.CanonicalForm()
	if err != nil {
		return
	}

	// credentialStatus itself IS defined by the VC 2.0 core context, so the
	// entry's id still appears. What disappears is every property that
	// carries the machine-readable reference - which is the whole point:
	// the signature would cover an opaque node and nothing a verifier could
	// resolve, and a holder could rewrite statusListUri freely.
	for _, gone := range []string{"statusListUri", "statusListIndex", "statusPurpose"} {
		if strings.Contains(canonical, gone) {
			t.Fatalf("expected %q to be dropped without its context; if JSON-LD now keeps undefined terms, the guard in this package needs rethinking.\n--- canonical form ---\n%s", gone, canonical)
		}
	}

	// And the type degrades to a relative IRI, which is itself refused
	// elsewhere - so the omission does not merely lose data, it produces a
	// credential that cannot validate.
	if !strings.Contains(canonical, "<TokenStatusListEntry>") {
		t.Fatalf("expected the undefined type to appear as a relative IRI.\n--- canonical form ---\n%s", canonical)
	}
}
