//go:build zknative

package verifier

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// zk-cred-vega's own nym_auth fixture: the published mdoc circuit's
// R1CS shapes, a reference proof made against them, and the statement
// that produced it. Staged by `make zk-native-lib-vega` beside the
// library rather than vendored here, so the fixture and the library it
// belongs to cannot drift apart - the same arrangement, and the same
// reason, as the Longfellow vectors in native_proof_zknative_test.go.
const vegaVectorsDir = "../../../third_party/zk-cred-vega/test-vectors/nymauth"

type vegaFixture struct {
	issuerKeyX, issuerKeyY string
	docType                string
	time                   string
	earliest, cutoff       string
	challengeDigest        string
	verifiers              []archiveVerifier
	shapes, proof          []byte
}

func loadVegaFixture(t *testing.T) vegaFixture {
	t.Helper()

	read := func(name string) []byte {
		path := filepath.Join(vegaVectorsDir, name)
		raw, err := os.ReadFile(path)
		require.NoErrorf(t, err, "the Vega nym_auth vectors are not staged (%s); run `make zk-native-lib-vega`", path)
		return raw
	}

	var verifierJSON struct {
		IssuerKey string `json:"issuer_key"`
		Mdoc      struct {
			DocType         string `json:"doc_type"`
			Time            string `json:"time"`
			Earliest        string `json:"earliest"`
			Cutoff          string `json:"cutoff"`
			ChallengeDigest string `json:"challenge_digest"`
		} `json:"mdoc"`
	}
	require.NoError(t, json.Unmarshal(read("verifier.json"), &verifierJSON))

	var pseudonymJSON struct {
		Verifiers []archiveVerifier `json:"verifiers"`
	}
	require.NoError(t, json.Unmarshal(read("pseudonym.json"), &pseudonymJSON))
	require.GreaterOrEqual(t, len(pseudonymJSON.Verifiers), 2,
		"the fixture must carry a second verifier, which is what makes the scoping test honest")

	decoder, err := zstd.NewReader(nil)
	require.NoError(t, err)
	defer decoder.Close()
	// The shapes are published compressed; the allowlist pins, and this
	// ABI takes, the DECOMPRESSED bytes.
	shapes, err := decoder.DecodeAll(read("shapes.zst"), nil)
	require.NoError(t, err, "decompressing the circuit shapes")

	// "x,y", hex, as the fixture writes Q.
	const sep = ","
	i := len(verifierJSON.IssuerKey) / 2
	require.Equal(t, sep, verifierJSON.IssuerKey[i:i+1], "issuer_key is two hex coordinates separated by a comma")

	return vegaFixture{
		issuerKeyX:      verifierJSON.IssuerKey[:i],
		issuerKeyY:      verifierJSON.IssuerKey[i+1:],
		docType:         verifierJSON.Mdoc.DocType,
		time:            verifierJSON.Mdoc.Time,
		earliest:        verifierJSON.Mdoc.Earliest,
		cutoff:          verifierJSON.Mdoc.Cutoff,
		challengeDigest: verifierJSON.Mdoc.ChallengeDigest,
		verifiers:       pseudonymJSON.Verifiers,
		shapes:          shapes,
		proof:           read("reference-proof.bin"),
	}
}

// request builds the verifier-side Request for one of the fixture's
// verifiers, exactly as the Longfellow fixture's does - including
// taking verifier_input from the fixture rather than deriving it, for
// the reason spelled out on archiveFixture.request.
func (f vegaFixture) request(t *testing.T, v archiveVerifier) Request {
	t.Helper()

	key := archiveIssuerKey(t, f.issuerKeyX, f.issuerKeyY)

	now, err := time.Parse(TimeLayout, f.time)
	require.NoError(t, err)

	transcript, err := MdocSessionTranscript(v.Origin, v.Nonce, nil)
	require.NoError(t, err)

	var verifierInput [32]byte
	raw, err := hex.DecodeString(v.VerifierInput)
	require.NoError(t, err)
	require.Len(t, raw, 32)
	copy(verifierInput[:], raw)

	return Request{
		IssuerKey: key,
		Now:       now,
		Inputs: []CircuitInput{{
			FunctionID: FunctionAgeCheck,
			Values: map[string][]byte{
				InputEarliest: []byte(f.earliest),
				InputCutoff:   []byte(f.cutoff),
			},
		}},
		SupportedFunctions: []string{FunctionAgeCheck},
		SessionTranscript:  transcript,
		DocType:            f.docType,
		VerifierInput:      verifierInput,
	}
}

// This repo derives the challenge digest the proof is bound to, from
// the verifier's own origin and nonce. The fixture states what that
// digest must come out as.
//
// Checked separately from the proof so the two failures are
// distinguishable: a wrong e2 and a bad proof both end in "the proof
// did not verify", and only one of them is this repo's bug.
func TestVegaFixtureChallengeDigestMatchesOurDerivation(t *testing.T) {
	f := loadVegaFixture(t)
	v := f.verifiers[0]

	e2, err := MdocE2(v.Origin, v.Nonce, f.docType, nil)
	require.NoError(t, err)
	assert.Equal(t, f.challengeDigest, hex.EncodeToString(e2[:]),
		"our e2 must be the one the fixture's proof was bound to")
}

// A REAL Vega nym_auth proof, verified through this repo's binding.
//
// This is the test the Vega backend exists to pass. Everything around
// it is plumbing that can be wrong in ways only a real proof catches -
// a coordinate the wrong way round, a statement field in the wrong
// slot, a digest passed where its hex was meant.
func TestVegaVerifierAcceptsAReferenceProof(t *testing.T) {
	f := loadVegaFixture(t)
	v := f.verifiers[0]

	backend, err := NewVegaVerifier(f.shapes)
	require.NoError(t, err, "deriving the verifier keys from the published shapes")
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	want := pseudonymBytes(t, v.Pseudonym)
	got, err := backend.Verify(f.request(t, v), want, f.proof)
	require.NoError(t, err, "the reference proof must verify")
	assert.Equal(t, want, got, "the revealed pseudonym must be the fixture's")
}

// The pseudonym is scoped to the verifier: the same proof under
// another verifier's input must not hand back that verifier's
// pseudonym. If it did, one verifier could compute another's and the
// scoping that makes these identifiers pairwise would be decorative.
func TestVegaVerifierDoesNotProduceAnotherVerifiersPseudonym(t *testing.T) {
	f := loadVegaFixture(t)
	mine, theirs := f.verifiers[0], f.verifiers[1]
	require.NotEqual(t, mine.Pseudonym, theirs.Pseudonym, "the two verifiers must differ in the fixture")

	backend, err := NewVegaVerifier(f.shapes)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	// My proof, their statement and their claimed pseudonym.
	got, err := backend.Verify(f.request(t, theirs), pseudonymBytes(t, theirs.Pseudonym), f.proof)
	require.Error(t, err, "a proof made for one verifier must not verify for another")
	assert.Equal(t, [32]byte{}, got, "no pseudonym may be returned on a refusal")
}

// A claimed pseudonym the proof does not reveal is a DIFFERENT fact
// from a proof that does not verify, and is reported as one: the proof
// is sound, and the response's results disagree with it.
func TestVegaVerifierRefusesAMismatchedClaim(t *testing.T) {
	f := loadVegaFixture(t)
	v := f.verifiers[0]

	backend, err := NewVegaVerifier(f.shapes)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	claimed := pseudonymBytes(t, v.Pseudonym)
	claimed[0] ^= 0xff

	got, err := backend.Verify(f.request(t, v), claimed, f.proof)
	require.ErrorIs(t, err, ErrPseudonymMismatch)
	assert.Equal(t, [32]byte{}, got, "no pseudonym may be returned on a refusal")
}

// A tampered proof is refused - the premise every test above depends
// on. Without it they would pass against bytes nothing checked.
func TestVegaVerifierRefusesATamperedProof(t *testing.T) {
	f := loadVegaFixture(t)
	v := f.verifiers[0]

	backend, err := NewVegaVerifier(f.shapes)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	tampered := append([]byte(nil), f.proof...)
	tampered[len(tampered)/2] ^= 0x01

	got, err := backend.Verify(f.request(t, v), pseudonymBytes(t, v.Pseudonym), tampered)
	require.Error(t, err, "a proof with a flipped bit must not verify")
	assert.Equal(t, [32]byte{}, got)
}
