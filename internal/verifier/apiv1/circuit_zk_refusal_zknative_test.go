//go:build zknative

package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three refusals on the cgo path. They exist only in a build that can
// actually check a proof, which is why they live behind the tag - and why
// no default-build test could reach the code that returns them.
func TestZkpReqProofRefusalsAreClassified(t *testing.T) {
	client := refusalClient(t, &fakeTrustEvaluator{trusted: true})

	// A real key: a nil one trips an earlier internal-invariant guard,
	// which is deliberately NOT a refusal - it is this verifier losing
	// track of its own state, not a wallet sending something wrong.
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// A handle the request asks for and the presentation does not carry.
	// Unreachable after response validation, which requires exactly the
	// request's handles; checked because the alternative is verifying
	// against a zero pseudonym.
	t.Run("no pseudonym for a requested handle", func(t *testing.T) {
		_, err := client.verifyCircuitZkPresentation(
			t.Context(),
			openid4vp.ZkpPresentation{Pseudonyms: map[string][]byte{}},
			circuitZkSession{},
			[]openid4vp.ReqItem{{FnID: openid4vp.FunctionPseudonym, Return: "nym"}},
			&issuerKey.PublicKey,
		)
		assertRefusal(t, err, CodeZkpReqNoPseudonym)
	})

	// Fail closed. The proof is one proof over the whole request and the
	// only way this build has to check it is a pseudonym item's Verify,
	// so with no pseudonym item there is nothing verifying anything.
	// This is the hole that let a predicate-only presentation through
	// once already.
	t.Run("a predicate-only request verifies nothing", func(t *testing.T) {
		_, err := client.verifyCircuitZkPresentation(
			t.Context(),
			openid4vp.ZkpPresentation{Pseudonyms: map[string][]byte{}},
			circuitZkSession{},
			[]openid4vp.ReqItem{{FnID: openid4vp.FunctionAgeCheck, Return: "age"}},
			&issuerKey.PublicKey,
		)
		assertRefusal(t, err, CodeZkpReqNothingChecked)
	})
}

// CodeZkpReqProofDidNotVerify is returned when the native verifier
// rejects the proof for a handle. Asserted through the refusal
// constructor rather than by producing an invalid proof against a real
// circuit: loading one costs a circuit artifact this test has no
// business depending on, and what is under test here is the CLASSIFYING,
// not libzk's verdict. The verdict itself is covered by the archive
// proof tests in pkg/nymauth/verifier.
func TestZkpReqProofDidNotVerifyIsClassified(t *testing.T) {
	err := refuseZkpReq(CodeZkpReqProofDidNotVerify, `the proof did not verify for handle "nym"`, nil)
	require.Error(t, err)
	assertRefusal(t, err, CodeZkpReqProofDidNotVerify)
	assert.Contains(t, err.Error(), "nym", "a prover needs to know which handle failed")
}
