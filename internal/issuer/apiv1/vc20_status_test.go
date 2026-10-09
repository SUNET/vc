package apiv1

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vc20/contextstore"
	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

func vc20Builder(t *testing.T, statusEnabled bool) *Client {
	t.Helper()
	return &Client{cfg: &model.Cfg{Issuer: &model.Issuer{
		JWTAttribute:     model.JWTAttribute{Issuer: "https://issuer.example.com"},
		VC20StatusEnable: &statusEnabled,
	}}}
}

func buildVC20(t *testing.T, status *statusAllocation) map[string]any {
	return buildVC20WithStatusEnabled(t, status, true)
}

func buildVC20WithStatusEnabled(t *testing.T, status *statusAllocation, enabled bool) map[string]any {
	t.Helper()
	raw, err := vc20Builder(t, enabled).buildVC20CredentialJSON(
		"urn:uuid:11111111-2222-3333-4444-555555555555",
		[]string{"VerifiableCredential"},
		nil, // additionalContexts: this test is about the status reference
		map[string]any{"id": "did:example:holder"},
		time.Now().UTC(),
		nil, // validUntil
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

// TestVC20StatusIsOffByDefault: with the flag off no entry is allocated at
// all, so nothing reaches buildVC20CredentialJSON and the credential carries
// no status. The context namespace is a placeholder no third party can
// dereference and no verifier checks the result yet, so a credential
// emitted with a status would LOOK revocable without being so - worse than
// emitting none, because the reference invites reliance on it.
func TestVC20StatusIsOffByDefault(t *testing.T) {
	cred := buildVC20WithStatusEnabled(t, nil, false)

	require.NotContains(t, cred, "credentialStatus",
		"VC 2.0 status must not be emitted unless issuer.vc20_status_enable is explicitly true")

	contexts, ok := cred["@context"].([]any)
	require.True(t, ok)
	require.Len(t, contexts, 1, "the placeholder context must not be published either")
	require.Equal(t, credential.ContextV2, contexts[0])
}

// TestVC20StatusUnsetConfigIsOff pins the default itself: a nil pointer is
// off, so the feature cannot arrive by upgrade.
func TestVC20StatusUnsetConfigIsOff(t *testing.T) {
	c := &Client{cfg: &model.Cfg{Issuer: &model.Issuer{
		JWTAttribute: model.JWTAttribute{Issuer: "https://issuer.example.com"},
	}}}
	require.False(t, c.vc20StatusEnabled())
}

// countingAllocator records how many times an allocation was asked for.
type countingAllocator struct{ calls int }

func (a *countingAllocator) Allocate(context.Context) (*statusAllocation, error) {
	a.calls++
	return &statusAllocation{Index: 1, URI: "https://status.example.com/statuslists/1", Backend: "status_service"}, nil
}
func (a *countingAllocator) Invalidate(context.Context, *statusAllocation) {}

// TestVC20StatusDisabledAllocatesNothing: with the flag off the credential
// carries no status, so asking for an entry consumes a remote slot per
// issuance for a credential that can never use it - and makes
// degraded_mode "fail" block a format that is deliberately non-revocable
// here.
func TestVC20StatusDisabledAllocatesNothing(t *testing.T) {
	enabled := false
	alloc := &countingAllocator{}
	c := &Client{
		cfg:             &model.Cfg{Issuer: &model.Issuer{VC20StatusEnable: &enabled}},
		log:             logger.NewSimple("test"),
		statusAllocator: alloc,
	}

	got, err := c.allocateVC20Status(t.Context())
	require.NoError(t, err)
	require.Nil(t, got)
	require.Zero(t, alloc.calls, "no entry may be allocated for a credential that will carry no status")
}

// TestVC20StatusEnabledDoesAllocate is the other half, so the gate is not
// simply refusing always.
func TestVC20StatusEnabledDoesAllocate(t *testing.T) {
	enabled := true
	alloc := &countingAllocator{}
	c := &Client{
		cfg:             &model.Cfg{Issuer: &model.Issuer{VC20StatusEnable: &enabled}},
		log:             logger.NewSimple("test"),
		statusAllocator: alloc,
	}

	got, err := c.allocateVC20Status(t.Context())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, 1, alloc.calls)
}
