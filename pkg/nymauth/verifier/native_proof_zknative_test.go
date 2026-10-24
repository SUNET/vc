//go:build zknative

package verifier

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The circuits archive's own nym_auth fixture: a real proof, the
// circuit it was made against, and the request values that produced it.
// Staged by `make zk-native-lib` beside the library (see that target),
// rather than vendored here, so the fixture and the library it belongs
// to can never drift apart.
const nymauthVectorsDir = "../../../third_party/zk-cred-longfellow/test-vectors/nymauth"

// The archive circuit's catalog parameters. Hardcoded because the
// archive ships the artifact but not its descriptor - and safely so:
// the loader checks the artifact against its own allowlist entry and
// refuses it outright if these do not match, so a stale constant here
// is a loud load failure, never a verification that passes against the
// wrong circuit.
var archiveParams = CircuitParams{
	BlockEncHash:  6983,
	BlockEncSig:   4679,
	HashCircuitID: "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729",
	SigCircuitID:  "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb",
}

type archiveVerifier struct {
	ClientID      string `json:"client_id"`
	Origin        string `json:"origin"`
	Nonce         string `json:"nonce"`
	VerifierInput string `json:"verifier_input"`
	Pseudonym     string `json:"pseudonym"`
}

type archiveFixture struct {
	issuerKeyX, issuerKeyY string
	docType                string
	time                   string
	earliest, cutoff       string
	verifiers              []archiveVerifier
	circuit, proof         []byte
}

func loadArchiveFixture(t *testing.T) archiveFixture {
	t.Helper()

	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(nymauthVectorsDir, name))
		require.NoErrorf(t, err, "the nym_auth vectors are not staged; run `make zk-native-lib`")
		return raw
	}

	var verifierJSON struct {
		IssuerKey string `json:"issuer_key"`
		Mdoc      struct {
			DocType  string `json:"doc_type"`
			Time     string `json:"time"`
			Earliest string `json:"earliest"`
			Cutoff   string `json:"cutoff"`
		} `json:"mdoc"`
	}
	require.NoError(t, json.Unmarshal(read("verifier.json"), &verifierJSON))

	var pseudonymJSON struct {
		Verifiers []archiveVerifier `json:"verifiers"`
	}
	require.NoError(t, json.Unmarshal(read("pseudonym.json"), &pseudonymJSON))
	require.GreaterOrEqual(t, len(pseudonymJSON.Verifiers), 2)

	decoder, err := zstd.NewReader(nil)
	require.NoError(t, err)
	defer decoder.Close()
	circuit, err := decoder.DecodeAll(read("mdoc-circuits.zst"), nil)
	require.NoError(t, err)

	// "x,y", hex, as the archive writes Q.
	const sep = ","
	i := len(verifierJSON.IssuerKey) / 2
	require.Equal(t, sep, verifierJSON.IssuerKey[i:i+1], "issuer_key is two hex coordinates separated by a comma")

	return archiveFixture{
		issuerKeyX: verifierJSON.IssuerKey[:i],
		issuerKeyY: verifierJSON.IssuerKey[i+1:],
		docType:    verifierJSON.Mdoc.DocType,
		time:       verifierJSON.Mdoc.Time,
		earliest:   verifierJSON.Mdoc.Earliest,
		cutoff:     verifierJSON.Mdoc.Cutoff,
		verifiers:  pseudonymJSON.Verifiers,
		circuit:    circuit,
		proof:      read("mdoc-proof.bin"),
	}
}

// request builds the verifier-side Request for one of the archive's
// verifiers.
//
// verifier_input is read from the fixture AND derived from the
// fixture's own client_id, and the two must agree.
//
// It used to be read only, with a comment saying why: the archive
// hashes the PREFIXED Client Identifier, this package refused to derive
// that, and the prediction recorded here was that a deployment whose
// provers follow the archive would produce pseudonyms this verifier
// never reproduces. v0.4 settled it the archive's way, so the
// workaround becomes the cross-check it was standing in for - end to
// end, from the published identifier to the pseudonym in the proof.
func (f archiveFixture) request(t *testing.T, v archiveVerifier) Request {
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

	derived, err := VerifierInput(v.ClientID)
	require.NoErrorf(t, err, "the archive's client_id %q is not a verifier_id this package will derive from", v.ClientID)
	require.Equalf(t, hex.EncodeToString(raw), hex.EncodeToString(derived[:]),
		"this package derives a different verifier_input from client_id %q than the archive published, so its pseudonyms would match nobody's", v.ClientID)

	return Request{
		IssuerKey: key,
		Now:       now,
		// The archive's own circuit inputs, rather than an AgeCheck
		// rendered into them: the fixture states the window the proof
		// was made against, and AgeCheck's mapping is agecheck_test's
		// subject.
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

// archiveIssuerKey rebuilds Q from the archive's two hex coordinates,
// and checks it is a point on P-256 - through crypto/ecdh, which
// validates, rather than by assembling the struct and trusting it.
func archiveIssuerKey(t *testing.T, xHex, yHex string) *ecdsa.PublicKey {
	t.Helper()
	x, ok := new(big.Int).SetString(xHex, 16)
	require.Truef(t, ok, "issuer key x is not hex: %q", xHex)
	y, ok := new(big.Int).SetString(yHex, 16)
	require.Truef(t, ok, "issuer key y is not hex: %q", yHex)

	sec1 := make([]byte, 1+2*coordinateBytes)
	sec1[0] = 4
	x.FillBytes(sec1[1 : 1+coordinateBytes])
	y.FillBytes(sec1[1+coordinateBytes:])
	_, err := ecdh.P256().NewPublicKey(sec1)
	require.NoError(t, err, "the archive issuer key must be a point on P-256")

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

func pseudonymBytes(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.Len(t, raw, 32)
	var out [32]byte
	copy(out[:], raw)
	return out
}

// The archive's proof verifies, and the pseudonym it reports is the
// archive's. This is the test that says the binding is wired to the
// real cryptographic check rather than to a status code that happens to
// be zero.
func TestArchiveProofVerifies(t *testing.T) {
	f := loadArchiveFixture(t)

	v, err := NewNativeVerifier(f.circuit, archiveParams)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, v.Close()) })

	claimed := pseudonymBytes(t, f.verifiers[0].Pseudonym)
	got, err := v.Verify(f.request(t, f.verifiers[0]), claimed, f.proof)
	require.NoError(t, err)
	assert.Equal(t, claimed, got)
}

// Everything the request binds the proof to has to be load-bearing. If
// any of these verified, the proof would be checked against a statement
// other than the one the verifier asked for.
func TestArchiveProofIsRefusedAgainstAnythingElse(t *testing.T) {
	f := loadArchiveFixture(t)

	v, err := NewNativeVerifier(f.circuit, archiveParams)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, v.Close()) })

	first, second := f.verifiers[0], f.verifiers[1]
	firstPseudonym := pseudonymBytes(t, first.Pseudonym)

	t.Run("another verifier's request and pseudonym", func(t *testing.T) {
		_, err := v.Verify(f.request(t, second), pseudonymBytes(t, second.Pseudonym), f.proof)
		assert.Error(t, err, "a pseudonym is pairwise; one verifier's proof must not verify for another")
	})

	t.Run("another verifier's pseudonym", func(t *testing.T) {
		_, err := v.Verify(f.request(t, first), pseudonymBytes(t, second.Pseudonym), f.proof)
		assert.Error(t, err)
	})

	t.Run("a tampered proof", func(t *testing.T) {
		tampered := append([]byte{}, f.proof...)
		tampered[len(tampered)/2] ^= 0x01
		_, err := v.Verify(f.request(t, first), firstPseudonym, tampered)
		assert.Error(t, err)
	})

	t.Run("a widened age window", func(t *testing.T) {
		r := f.request(t, first)
		r.Inputs[0].Values[InputCutoff] = []byte("2030-01-01")
		_, err := v.Verify(r, firstPseudonym, f.proof)
		assert.Error(t, err, "the proof is bound to the window it was made against")
	})

	t.Run("another verification time", func(t *testing.T) {
		r := f.request(t, first)
		r.Now = r.Now.AddDate(1, 0, 0)
		_, err := v.Verify(r, firstPseudonym, f.proof)
		assert.Error(t, err)
	})
}

// A circuit the loader's allowlist does not recognise is refused before
// it is parsed, so a wrong artifact cannot become a verifier at all.
func TestNativeVerifierRefusesAnUnknownCircuit(t *testing.T) {
	f := loadArchiveFixture(t)

	tampered := append([]byte{}, f.circuit...)
	tampered[len(tampered)/2] ^= 0x01
	v, err := NewNativeVerifier(tampered, archiveParams)
	assert.Error(t, err)
	assert.Nil(t, v)

	wrongParams := archiveParams
	wrongParams.BlockEncHash++
	v, err = NewNativeVerifier(f.circuit, wrongParams)
	assert.Error(t, err)
	assert.Nil(t, v)
}
