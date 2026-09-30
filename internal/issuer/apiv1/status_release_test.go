package apiv1

import (
	"context"
	"testing"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/require"
)

// recordingAllocator hands out one entry and records every invalidation.
type recordingAllocator struct {
	allocated   int
	invalidated []*statusAllocation
	// refused counts calls that arrived on a dead context - what a real
	// backend call would fail on.
	refused int
}

func (a *recordingAllocator) Allocate(context.Context) (*statusAllocation, error) {
	a.allocated++
	return &statusAllocation{
		Index:   int64(a.allocated),
		URI:     "https://status.example.com/statuslists/1",
		Backend: "status_service",
	}, nil
}

// Invalidate records the call only when the context is still live, the way
// a real allocator behaves: both implementations make an RPC, and an RPC on
// a cancelled context fails without reaching the backend.
func (a *recordingAllocator) Invalidate(ctx context.Context, alloc *statusAllocation) {
	if ctx.Err() != nil {
		a.refused++
		return
	}
	a.invalidated = append(a.invalidated, alloc)
}

// TestReleaseUnlessIssued covers the guard itself: it hands the entry back
// unless the caller marked the issuance done, and does nothing when there
// was no entry to begin with (the degraded-mode case).
func TestReleaseUnlessIssued(t *testing.T) {
	alloc := &statusAllocation{Index: 7, URI: "https://status.example.com/statuslists/1", Backend: "status_service"}

	t.Run("not issued releases", func(t *testing.T) {
		rec := &recordingAllocator{}
		c := &Client{statusAllocator: rec, log: logger.NewSimple("test")}
		issued := false
		c.releaseUnlessIssued(t.Context(), alloc, &issued)
		require.Len(t, rec.invalidated, 1)
		require.Equal(t, int64(7), rec.invalidated[0].Index)
	})

	t.Run("issued keeps", func(t *testing.T) {
		rec := &recordingAllocator{}
		c := &Client{statusAllocator: rec, log: logger.NewSimple("test")}
		issued := true
		c.releaseUnlessIssued(t.Context(), alloc, &issued)
		require.Empty(t, rec.invalidated)
	})

	t.Run("nothing allocated", func(t *testing.T) {
		rec := &recordingAllocator{}
		c := &Client{statusAllocator: rec, log: logger.NewSimple("test")}
		issued := false
		c.releaseUnlessIssued(t.Context(), nil, &issued)
		require.Empty(t, rec.invalidated)
	})

	// A cancelled request is one of the ways issuance fails, so the release
	// must not inherit that cancellation - it would guarantee the cleanup
	// fails exactly when it is needed.
	t.Run("a cancelled request still releases", func(t *testing.T) {
		rec := &recordingAllocator{}
		c := &Client{statusAllocator: rec, log: logger.NewSimple("test")}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		issued := false
		c.releaseUnlessIssued(ctx, alloc, &issued)
		require.Len(t, rec.invalidated, 1)
		require.Zero(t, rec.refused, "the release must not inherit the request's cancellation")
	})
}

// TestMakeVC20ReleasesTheEntryWhenSigningFails is the call-site half: the
// guard only matters if the handler installs it. Signing fails here, which
// is one of four post-allocation failure paths in this handler and was
// reachable without any of them handing the entry back.
func TestMakeVC20ReleasesTheEntryWhenSigningFails(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	enabled := true
	client.cfg.Issuer.VC20StatusEnable = &enabled
	rec := &recordingAllocator{}
	client.statusAllocator = rec

	// The credential is built and parsed, and then signing fails because
	// the key is not the type the cryptosuite needs.
	client.privateKey = nil

	_, err := client.MakeVC20(ctx, &CreateVC20Request{
		Scope:           "pid",
		DocumentData:    mockCredentialSubject,
		CredentialTypes: []string{"VerifiableCredential"},
		Cryptosuite:     openid4vp.CryptosuiteECDSA2019,
	})
	require.Error(t, err)
	require.Equal(t, 1, rec.allocated, "the entry really was allocated before the failure")
	require.Len(t, rec.invalidated, 1, "a credential that was never issued must not leave a VALID entry behind")
}

// TestMakeVC20KeepsTheEntryWhenIssuanceSucceeds is the other half, so the
// guard is not simply invalidating everything.
func TestMakeVC20KeepsTheEntryWhenIssuanceSucceeds(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	enabled := true
	client.cfg.Issuer.VC20StatusEnable = &enabled
	rec := &recordingAllocator{}
	client.statusAllocator = rec

	reply, err := client.MakeVC20(ctx, &CreateVC20Request{
		Scope:           "pid",
		DocumentData:    mockCredentialSubject,
		CredentialTypes: []string{"VerifiableCredential"},
		Cryptosuite:     openid4vp.CryptosuiteECDSA2019,
	})
	require.NoError(t, err)
	require.NotEmpty(t, reply.Credential)
	require.Equal(t, 1, rec.allocated)
	require.Empty(t, rec.invalidated, "an issued credential's entry stays VALID")
}

// TestMakeSDJWTReleasesTheEntryWhenBuildFails: the same guard on the
// SD-JWT path, where a malformed VCTM fails the build after allocation.
func TestMakeSDJWTReleasesTheEntryWhenBuildFails(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	rec := &recordingAllocator{}
	client.statusAllocator = rec

	// Every required field present, so validation passes and allocation
	// happens - and then the VCTM fails to parse inside the builder.
	_, err := client.MakeSDJWT(ctx, &CreateCredentialRequest{
		Scope:        "ehic",
		DocumentData: mockEhic,
		VCTM:         []byte(`{not valid json`),
		Integrity:    "sha256-notreal",
		JWK: &apiv1_issuer.Jwk{
			Kty: "EC", Crv: "P-256",
			X: "f83OJ3D2xF4c3hXhN3k1j5x5mX5Z5x5Z5x5Z5x5Z5x5Z",
			Y: "x_FEzRu9mX5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5x5Z5",
		},
	})
	require.Error(t, err)
	require.Equal(t, 1, rec.allocated)
	require.Len(t, rec.invalidated, 1, "the SD-JWT path must hand the entry back too")
}
