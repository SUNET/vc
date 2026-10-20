//go:build zknative

package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/nymauth/verifier"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// These run only in a zknative build, which is the only build where
// verifyCircuitZkPresentation does anything. The !zknative stub
// refuses everything, so a default build cannot reach what is checked
// here - and before this file existed, no test compiled the cgo
// implementation at all. That is how the hole below survived: the
// `make build-verifier-zknative` step compiled it, nothing ran it.

func zknativeTestSession(t *testing.T) (circuitZkSession, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// A well-formed three-item transcript; nothing here reaches the
	// native library, so its contents only have to be well-formed.
	transcript, err := verifier.MdocSessionTranscript(
		"https://verifier.example", "pOA0oqEAhLnqug2r7Ve4tQ", nil)
	require.NoError(t, err)

	return circuitZkSession{
		Transcript: transcript,
		DocType:    "eu.europa.ec.eudi.nym_auth.1",
		Now:        time.Now(),
	}, &key.PublicKey
}

// A presentation that asks only for a PREDICATE must be refused.
//
// The proof is one proof over the whole request, and the only way
// this build has to check it is a pseudonym item's Verify. With no
// pseudonym item that call never happens, so nothing looks at the
// proof - and a nil error here is the caller's signal to cache
// "satisfied": true as a verified fact. A holder could then send any
// base64url bytes as the proof, with a genuine public issuer chain,
// and have the predicate believed.
func TestCircuitZkPredicateOnlyPresentationIsRefused(t *testing.T) {
	session, issuerKey := zknativeTestSession(t)
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{}}}

	items := []openid4vp.ReqItem{{
		FnID:   openid4vp.FunctionAgeCheck,
		Return: "age-range-123",
		Params: map[string]any{"ge": "2008-10-10", "le": "2013-10-09"},
	}}
	// Proof bytes nothing would accept, which is the point: no part
	// of this presentation is checkable, so none of it may pass.
	presentation := openid4vp.ZkpPresentation{
		SystemID: "urn:circuits:longfellow:nym_auth:v1",

		Proof:     []byte("not a proof"),
		Satisfied: []string{"age-range-123"},
	}

	verified, err := client.verifyCircuitZkPresentation(t.Context(), presentation, session, items, issuerKey)
	require.Error(t, err, "a presentation whose proof nothing checked must not verify")
	assert.Nil(t, verified)
	assert.Contains(t, err.Error(), "no verification path")
}

// The same refusal with NO items at all: there is nothing to check,
// which is not the same as everything checking out.
func TestCircuitZkNoItemsIsRefused(t *testing.T) {
	session, issuerKey := zknativeTestSession(t)
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{}}}

	verified, err := client.verifyCircuitZkPresentation(
		t.Context(), openid4vp.ZkpPresentation{Proof: []byte("not a proof")}, session, nil, issuerKey)
	require.Error(t, err)
	assert.Nil(t, verified)
}

// A missing issuer key is refused before anything else: the key is
// what the circuit proves a signature under, so there is nothing to
// verify against without it.
func TestCircuitZkNoIssuerKeyIsRefused(t *testing.T) {
	session, _ := zknativeTestSession(t)
	client := &Client{cfg: &model.Cfg{Verifier: &model.Verifier{}}}

	items := []openid4vp.ReqItem{{FnID: openid4vp.FunctionAgeCheck, Return: "age-1"}}
	_, err := client.verifyCircuitZkPresentation(
		t.Context(), openid4vp.ZkpPresentation{}, session, items, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no issuer key")
}
