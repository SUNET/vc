//go:build zknative

package apiv1

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/nymauth"
	"github.com/SUNET/vc/pkg/nymauth/circuits"
	"github.com/SUNET/vc/pkg/nymauth/verifier"
)

// Which library opens an allowed artifact is decided by the entry's
// proof system, and these check that it is decided rather than
// defaulted. The failure this guards against is quiet: before the
// dispatch existed, every entry was handed to Longfellow, and a Vega
// entry's shapes reached a loader that cannot read them - which looks
// to an operator like a bad artifact rather than a verifier that never
// learned the system.
//
// zknative only, because a default build cannot construct either
// verifier: both constructors return ErrNativeNotBuilt, so there would
// be nothing to tell apart.

// The staged fixtures, both of them the real published circuits - the
// point of the cross-feed case below is that each is genuinely the
// other's library's artifact, not a handful of bytes.
const (
	longfellowCircuitPath = "../../../third_party/zk-cred-longfellow/test-vectors/nymauth/mdoc-circuits.zst"
	vegaShapesPath        = "../../../third_party/zk-cred-vega/test-vectors/nymauth/shapes.zst"
)

// The Longfellow archive circuit's catalog parameters, as
// pkg/nymauth/verifier's own fixture states them. A stale value here
// is a load failure, never a verification against the wrong circuit:
// the loader checks the artifact against them.
var longfellowFixtureParams = circuits.Entry{
	SystemID:      nymauth.SystemLongfellowNymAuth,
	Config:        "default",
	BlockEncHash:  6983,
	BlockEncSig:   4679,
	HashCircuitID: "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729",
	SigCircuitID:  "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb",
}

// decompressedArtifact reads one of the staged .zst fixtures. The
// allowlist pins, and both ABIs take, the DECOMPRESSED bytes.
func decompressedArtifact(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoErrorf(t, err, "the nym_auth vectors are not staged (%s); run `make zk-native-lib zk-native-lib-vega`",
		filepath.Clean(path))

	decoder, err := zstd.NewReader(nil)
	require.NoError(t, err)
	defer decoder.Close()
	artifact, err := decoder.DecodeAll(raw, nil)
	require.NoError(t, err)
	return artifact
}

// A Longfellow entry loads Longfellow's verifier.
func TestNymAuthBackendForALongfellowEntryIsTheLongfellowVerifier(t *testing.T) {
	backend, err := newNymAuthBackend(longfellowFixtureParams, decompressedArtifact(t, longfellowCircuitPath))
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	assert.IsType(t, (*verifier.NativeVerifier)(nil), backend)
}

// A Vega entry loads Vega's, from the same call and with no
// parameters: its artifact is R1CS shapes, and the verifier key is
// derived from them rather than named beside them.
func TestNymAuthBackendForAVegaEntryIsTheVegaVerifier(t *testing.T) {
	entry := circuits.Entry{SystemID: nymauth.SystemVegaNymAuth, Config: "default"}

	backend, err := newNymAuthBackend(entry, decompressedArtifact(t, vegaShapesPath))
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	assert.IsType(t, (*verifier.VegaVerifier)(nil), backend)
}

// The system decides, not the artifact. Vega's shapes under a
// Longfellow entry must fail to load rather than be read by whichever
// library happens to be wired in - this is the case that failed
// silently before, and it fails loudly now.
func TestNymAuthBackendDoesNotOpenVegaShapesWithLongfellow(t *testing.T) {
	entry := longfellowFixtureParams
	backend, err := newNymAuthBackend(entry, decompressedArtifact(t, vegaShapesPath))
	require.Error(t, err, "Longfellow must not load an artifact that belongs to another proof system")
	assert.Nil(t, backend)
}

// And the other way round, so neither direction is an accident of
// which library is more tolerant of the bytes it is handed.
func TestNymAuthBackendDoesNotOpenALongfellowCircuitWithVega(t *testing.T) {
	entry := circuits.Entry{SystemID: nymauth.SystemVegaNymAuth, Config: "default"}
	backend, err := newNymAuthBackend(entry, decompressedArtifact(t, longfellowCircuitPath))
	require.Error(t, err, "Vega must not load an artifact that belongs to another proof system")
	assert.Nil(t, backend)
}

// An entry naming a system this build has no verifier for is refused.
//
// Unreachable through a loaded allowlist, which runs
// nymauth.CheckSystemID when it is built - and checked anyway, because
// the alternative to a backend is no verification at all.
func TestNymAuthBackendRefusesAnUnknownSystem(t *testing.T) {
	entry := circuits.Entry{SystemID: "urn:circuits:nonesuch:nym_auth:v1", Config: "default"}

	backend, err := newNymAuthBackend(entry, decompressedArtifact(t, vegaShapesPath))
	require.Error(t, err)
	assert.Nil(t, backend)
	assert.Contains(t, err.Error(), "urn:circuits:nonesuch:nym_auth:v1",
		"the refusal must name the system, so an operator can find the entry that asked for it")
}
