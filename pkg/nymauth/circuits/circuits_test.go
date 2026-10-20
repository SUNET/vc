package circuits

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/nymauth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// artifact writes a circuit artifact and returns its path, digest and
// length.
func artifact(t *testing.T, content string) (path, digest string, size int64) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "circuit.bin")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:]), int64(len(content))
}

func entryFor(t *testing.T, config, content string) model.NymAuthCircuit {
	t.Helper()
	path, digest, size := artifact(t, content)
	return model.NymAuthCircuit{
		Config:         config,
		HashCircuitID:  "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729",
		SigCircuitID:   "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb",
		BlockEncHash:   6983,
		BlockEncSig:    4679,
		ArtifactPath:   path,
		ArtifactSHA256: digest,
		ArtifactBytes:  size,
	}
}

func TestAllowlistResolvesAndCaches(t *testing.T) {
	entry := entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
	list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
	require.NoError(t, err)

	assert.Equal(t, []string{nymauth.ConfigKnownOffenderMatchingSSC}, list.Configs())

	got, err := list.Artifact(t.Context(), nymauth.ConfigKnownOffenderMatchingSSC)
	require.NoError(t, err)
	assert.Equal(t, "a circuit", string(got))

	// Served from the cache afterwards: removing the file must not
	// change the answer, because the bytes were checked once and
	// cannot change.
	require.NoError(t, os.Remove(entry.ArtifactPath))
	again, err := list.Artifact(t.Context(), nymauth.ConfigKnownOffenderMatchingSSC)
	require.NoError(t, err)
	assert.Equal(t, got, again)
}

// Nothing outside the allowlist is ever loaded, and asking for a
// configuration that is not on it is an ordinary operator state
// rather than a fault.
func TestAllowlistRefusesAnUnknownConfiguration(t *testing.T) {
	list, err := NewAllowlist(model.NymAuthCircuits{
		Allow: []model.NymAuthCircuit{entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")},
	})
	require.NoError(t, err)

	_, err = list.Entry(nymauth.ConfigKnownOffenderMatchingPSC)
	assert.ErrorIs(t, err, ErrNoSuchConfig)

	_, err = list.Artifact(t.Context(), nymauth.ConfigKnownOffenderMatchingPSC)
	assert.ErrorIs(t, err, ErrNoSuchConfig)
}

// The artifact must be the one the operator allowed. The native
// loader checks too, but it answers with a status code; an operator
// reading "bad circuit" cannot tell a stale path from a wrong digest.
func TestAllowlistRefusesAnArtifactThatIsNotTheAllowedOne(t *testing.T) {
	t.Run("the wrong digest", func(t *testing.T) {
		entry := entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
		entry.ArtifactSHA256 = hex.EncodeToString(make([]byte, sha256.Size))
		list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
		require.NoError(t, err)

		_, err = list.Artifact(t.Context(), entry.Config)
		assert.ErrorContains(t, err, "hashes to")
	})

	t.Run("shorter than the allowlist says", func(t *testing.T) {
		entry := entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
		entry.ArtifactBytes++
		list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
		require.NoError(t, err)

		_, err = list.Artifact(t.Context(), entry.Config)
		assert.ErrorContains(t, err, "the allowlist says")
	})

	t.Run("longer than the allowlist says", func(t *testing.T) {
		// Detected rather than truncated to the declared length and
		// then hashed, which would make a longer artifact whose
		// prefix matches indistinguishable from the real one.
		entry := entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit and then some")
		entry.ArtifactBytes = int64(len("a circuit"))
		sum := sha256.Sum256([]byte("a circuit"))
		entry.ArtifactSHA256 = hex.EncodeToString(sum[:])
		list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
		require.NoError(t, err)

		_, err = list.Artifact(t.Context(), entry.Config)
		assert.ErrorContains(t, err, "the allowlist says")
	})

	t.Run("a path that is not there", func(t *testing.T) {
		entry := entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
		entry.ArtifactPath = filepath.Join(t.TempDir(), "absent.bin")
		list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
		require.NoError(t, err)

		_, err = list.Artifact(t.Context(), entry.Config)
		assert.ErrorContains(t, err, "circuit artifact")
	})
}

// A configuration is a build, so two builds for one configuration is
// a question with two answers. Refused at startup rather than
// resolved by order, which would verify against whichever the
// operator happened to write first.
func TestAllowlistRefusesTwoBuildsForOneConfiguration(t *testing.T) {
	first := entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
	second := entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "another circuit")

	_, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{first, second}})
	assert.ErrorContains(t, err, "a second circuit is allowed for configuration")
}

// Both configurations may be allowed at once, which is what a
// deployment verifying ssc and psc needs.
func TestAllowlistTakesBothConfigurations(t *testing.T) {
	list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{
		entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "the ssc circuit"),
		entryFor(t, nymauth.ConfigKnownOffenderMatchingPSC, "the psc circuit"),
	}})
	require.NoError(t, err)
	assert.Len(t, list.Configs(), 2)

	ssc, err := list.Artifact(t.Context(), nymauth.ConfigKnownOffenderMatchingSSC)
	require.NoError(t, err)
	psc, err := list.Artifact(t.Context(), nymauth.ConfigKnownOffenderMatchingPSC)
	require.NoError(t, err)
	assert.NotEqual(t, ssc, psc, "two configurations are two different builds")
}

// An entry this code cannot reason about is refused at startup.
func TestAllowlistRefusesAMalformedEntry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*model.NymAuthCircuit)
		want   string
	}{
		{"an unknown configuration", func(e *model.NymAuthCircuit) { e.Config = "something-else" }, "not a known-offender-matching configuration"},
		{"a non-hex circuit id", func(e *model.NymAuthCircuit) { e.HashCircuitID = "not-hex" }, "hash_circuit_id is not hex"},
		{"one circuit id used twice", func(e *model.NymAuthCircuit) { e.SigCircuitID = e.HashCircuitID }, "the same, which no real build has"},
		{"a digest that is not a SHA-256", func(e *model.NymAuthCircuit) { e.ArtifactSHA256 = "abcd" }, "64-character hex SHA-256"},
		{"no declared length", func(e *model.NymAuthCircuit) { e.ArtifactBytes = 0 }, "must be positive"},
		{"neither a path nor an id", func(e *model.NymAuthCircuit) { e.ArtifactPath = "" }, "exactly one of artifact_path and artifact_id"},
		{"both a path and an id", func(e *model.NymAuthCircuit) { e.ArtifactID = "urn:circuits:x" }, "exactly one of artifact_path and artifact_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
			tc.mutate(&entry)
			_, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
			assert.ErrorContains(t, err, tc.want)
		})
	}
}

// A catalog id with no sources is refused at startup, and a catalog
// id with sources is refused at load - honestly, because nothing
// resolves one yet and returning bytes from somewhere unintended
// would be worse than saying so.
func TestAllowlistOnCatalogIDs(t *testing.T) {
	entry := entryFor(t, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
	entry.ArtifactPath = ""
	entry.ArtifactID = "urn:circuits:longfellow:nym_auth:v1"

	_, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
	assert.ErrorContains(t, err, "no verifier.nym_auth.circuits.sources are configured")

	list, err := NewAllowlist(model.NymAuthCircuits{
		Sources: []string{"https://zk-circuits.fly.dev"},
		Allow:   []model.NymAuthCircuit{entry},
	})
	require.NoError(t, err)

	_, err = list.Artifact(t.Context(), entry.Config)
	assert.ErrorContains(t, err, "cannot resolve yet")
}
