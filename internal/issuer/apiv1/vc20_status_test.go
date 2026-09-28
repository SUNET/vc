package apiv1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vc20/contextstore"
	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

func vc20Builder(t *testing.T) *Client {
	t.Helper()
	return &Client{cfg: &model.Cfg{Issuer: &model.Issuer{
		JWTAttribute: model.JWTAttribute{Issuer: "https://issuer.example.com"},
	}}}
}

func buildVC20(t *testing.T, status *statusAllocation) map[string]any {
	t.Helper()
	raw, err := vc20Builder(t).buildVC20CredentialJSON(
		"urn:uuid:11111111-2222-3333-4444-555555555555",
		[]string{"VerifiableCredential"},
		map[string]any{"id": "did:example:holder"},
		time.Now().UTC(),
		nil,
		status,
	)
	require.NoError(t, err)

	var cred map[string]any
	require.NoError(t, json.Unmarshal(raw, &cred))
	return cred
}

// TestVC20CredentialCarriesItsStatus: VC 2.0 credentials carried no status
// reference at all, so none could ever be revoked.
func TestVC20CredentialCarriesItsStatus(t *testing.T) {
	cred := buildVC20(t, &statusAllocation{
		Index: 42,
		URI:   "https://status.example.com/statuslists/7",
	})

	entry, ok := cred["credentialStatus"].(map[string]any)
	require.True(t, ok, "credential carries no credentialStatus, so it cannot be revoked")
	require.Equal(t, contextstore.TokenStatusListEntryType, entry["type"])
	require.Equal(t, "https://status.example.com/statuslists/7", entry["statusListUri"])
	require.Equal(t, "42", entry["statusListIndex"])
	require.Equal(t, "revocation", entry["statusPurpose"])
}

// TestVC20StatusContextIsDeclared is the one that matters. vc signs VC 2.0
// with Data Integrity over canonicalized RDF, so if the context defining
// TokenStatusListEntry is not in @context, statusListUri and
// statusListIndex are dropped from the canonical form and the proof does
// not cover them - the status could be stripped or rewritten and the
// signature would still verify. See
// pkg/vc20/credential/status_canonicalization_test.go, which demonstrates
// exactly that disappearance.
func TestVC20StatusContextIsDeclared(t *testing.T) {
	cred := buildVC20(t, &statusAllocation{
		Index: 42,
		URI:   "https://status.example.com/statuslists/7",
	})

	contexts, ok := cred["@context"].([]any)
	require.True(t, ok)
	require.Len(t, contexts, 2)
	require.Equal(t, credential.ContextV2, contexts[0],
		"the VC 2.0 core context must stay first")
	require.Equal(t, contextstore.TokenStatusListContextURL, contexts[1],
		"without this context the status is not covered by the proof")
}

// TestVC20WithoutAnAllocationCarriesNeither: a credential issued without a
// status entry must not advertise revocability, and must not pull in a
// context it has no terms from.
func TestVC20WithoutAnAllocationCarriesNeither(t *testing.T) {
	cred := buildVC20(t, nil)

	require.NotContains(t, cred, "credentialStatus")

	contexts, ok := cred["@context"].([]any)
	require.True(t, ok)
	require.Len(t, contexts, 1)
	require.Equal(t, credential.ContextV2, contexts[0])
}
