package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// declineLandsMidVerification reproduces the window the fix closes.
//
// The handler reads the session, then verifies credentials, then records the
// outcome - and verification takes as long as it takes. This store hands the
// handler the session as it was when it looked (still open) and, once, records
// a decline underneath immediately afterwards. That is exactly a user
// declining while the wallet's presentation is in flight.
type declineLandsMidVerification struct {
	cache.AuthContextStore
	once sync.Once
}

func (s *declineLandsMidVerification) Get(ctx context.Context, query *cache.AuthorizationContext) (*cache.AuthorizationContext, error) {
	doc, err := s.AuthContextStore.Get(ctx, query)
	if err != nil || doc == nil {
		return doc, err
	}

	// A copy, so recording the decline below cannot change what the handler
	// is holding - MemoryStore.Get hands out the stored pointer.
	asRead := *doc

	s.once.Do(func() {
		declined := *doc
		declined.Status = cache.SessionStatusError
		declined.Error = "access_denied"
		declined.ErrorDescription = "the user declined"
		_, _ = s.AuthContextStore.ClaimOutcome(ctx, &declined)
	})

	return &asRead, nil
}

// A decline that lands while a presentation is being verified is NOT erased by
// that presentation: the presentation is told it lost, the refusal survives,
// and the browser is not notified of a completion it was never going to be
// shown.
//
// Driven through VerificationDirectPost with a real encrypted SD-JWT
// presentation, because the defect is in that handler. An earlier version of
// this test called ClaimOutcome directly, which meant reverting the handler to
// its unconditional Save would have left it passing while restoring the race -
// it tested the store, which pkg/cache's own contract tests already do.
//
// Before the fix both sides read, decided and then saved, with nothing holding
// the session across the three. The presentation's save carried the context as
// it had read it - open - so the refusal vanished from a session the browser
// had already been shown a refusal for, and /ui/completion and /ui/resume gave
// two different answers for it afterwards.
func TestADeclineDuringVerificationIsNotOverwritten(t *testing.T) {
	ctx := t.Context()

	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client, _ := CreateTestClientWithMock(t, nil)
	log := logger.NewSimple("test")
	notifyService, err := notify.New(ctx, client.cfg, log)
	require.NoError(t, err)
	client.notify = notifyService

	openid4vpClient, err := openid4vp.New(ctx, &openid4vp.Config{})
	require.NoError(t, err)
	client.openid4vp = openid4vpClient

	client.jwtTrustVerifier = trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
		TrustEvaluator: trust.NewAllowAllEvaluator(),
		JWKSResolver:   trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{}),
		ParseX5C:       func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
		ParseJWK:       jose.ParseJWKToPublicKey,
		Log:            log,
	})

	const (
		kid       = "racing-ephemeral-kid"
		state     = "racing-state"
		nonce     = "racing-nonce"
		scope     = "pid"
		sessionID = "racing-session"
		clientID  = "x509_san_dns:verifier.example.com"
	)
	_, ephemeralPubJWK, err := client.ephemeralEncryptionKey(ctx, kid)
	require.NoError(t, err)

	require.NoError(t, client.cacheService.AuthContext.Save(ctx, &cache.AuthorizationContext{
		SessionID:                sessionID,
		State:                    state,
		Nonce:                    nonce,
		ClientID:                 clientID,
		Scopes:                   []string{scope},
		EphemeralEncryptionKeyID: kid,
		Status:                   cache.SessionStatusAwaitingPresentation,
	}))

	// A listener on the session, so "no completion notification" is an
	// assertion rather than an inference from the returned error.
	listener := notifyService.OpenListener(sessionID)
	t.Cleanup(func() { notifyService.CloseListener(sessionID, listener) })

	// Wrapped only now, so the save above does not trip it. From here the
	// handler's first read of the session is what lands the decline.
	client.cacheService.AuthContext = &declineLandsMidVerification{
		AuthContextStore: client.cacheService.AuthContext,
	}

	vpResponse, err := json.Marshal(openid4vp.VPResponse{
		State: state,
		VPToken: map[string][]string{scope: {
			createTestSDJWT(t, sigKey, map[string]any{"given_name": "John", "birthdate": "1990-01-01"}, nonce, clientID),
		}},
	})
	require.NoError(t, err)

	encrypted, err := jwe.Encrypt(vpResponse,
		jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	require.NoError(t, err)

	reply, err := client.VerificationDirectPost(ctx, &VerificationDirectPostRequest{Response: string(encrypted)})

	require.ErrorIs(t, err, ErrSessionAlreadyAnswered,
		"a presentation that lost the race must say so, not report a completion")
	assert.Nil(t, reply, "and must hand the wallet no redirect to a result")

	stored, err := client.cacheService.AuthContext.GetByID(ctx, sessionID)
	require.NoError(t, err)
	assert.Equal(t, cache.SessionStatusError, stored.Status, "the refusal must survive")
	assert.Equal(t, "access_denied", stored.Error)
	assert.Equal(t, "the user declined", stored.ErrorDescription)
	assert.Empty(t, stored.VerifierResponseCode,
		"a declined session must not hand the browser a response code to fetch with")

	select {
	case msg := <-listener:
		t.Fatalf("the browser was notified of a completion for a declined session: %v", msg)
	case <-time.After(100 * time.Millisecond):
	}
}
