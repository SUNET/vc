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

func entryFor(t *testing.T, systemID, config, content string) model.NymAuthCircuit {
	t.Helper()
	path, digest, size := artifact(t, content)
	return model.NymAuthCircuit{
		SystemID:       systemID,
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
	entry := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
	list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
	require.NoError(t, err)

	assert.Equal(t, []string{nymauth.SystemLongfellowNymAuth + " " + nymauth.ConfigKnownOffenderMatchingSSC}, list.Allowed())

	got, err := list.Artifact(t.Context(), nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC)
	require.NoError(t, err)
	assert.Equal(t, "a circuit", string(got))

	// Served from the cache afterwards: removing the file must not
	// change the answer, because the bytes were checked once and
	// cannot change.
	require.NoError(t, os.Remove(entry.ArtifactPath))
	again, err := list.Artifact(t.Context(), nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC)
	require.NoError(t, err)
	assert.Equal(t, got, again)
}

// Nothing outside the allowlist is ever loaded, and asking for a
// configuration that is not on it is an ordinary operator state
// rather than a fault.
func TestAllowlistRefusesAnUnknownConfiguration(t *testing.T) {
	list, err := NewAllowlist(model.NymAuthCircuits{
		Allow: []model.NymAuthCircuit{entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")},
	})
	require.NoError(t, err)

	_, err = list.Entry(nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingPSC)
	assert.ErrorIs(t, err, ErrNoSuchCircuit)

	_, err = list.Artifact(t.Context(), nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingPSC)
	assert.ErrorIs(t, err, ErrNoSuchCircuit)
}

// The artifact must be the one the operator allowed. The native
// loader checks too, but it answers with a status code; an operator
// reading "bad circuit" cannot tell a stale path from a wrong digest.
func TestAllowlistRefusesAnArtifactThatIsNotTheAllowedOne(t *testing.T) {
	t.Run("the wrong digest", func(t *testing.T) {
		entry := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
		entry.ArtifactSHA256 = hex.EncodeToString(make([]byte, sha256.Size))
		list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
		require.NoError(t, err)

		_, err = list.Artifact(t.Context(), entry.SystemID, entry.Config)
		assert.ErrorContains(t, err, "hashes to")
	})

	t.Run("shorter than the allowlist says", func(t *testing.T) {
		entry := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
		entry.ArtifactBytes++
		list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
		require.NoError(t, err)

		_, err = list.Artifact(t.Context(), entry.SystemID, entry.Config)
		assert.ErrorContains(t, err, "the allowlist says")
	})

	t.Run("longer than the allowlist says", func(t *testing.T) {
		// Detected rather than truncated to the declared length and
		// then hashed, which would make a longer artifact whose
		// prefix matches indistinguishable from the real one.
		entry := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit and then some")
		entry.ArtifactBytes = int64(len("a circuit"))
		sum := sha256.Sum256([]byte("a circuit"))
		entry.ArtifactSHA256 = hex.EncodeToString(sum[:])
		list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
		require.NoError(t, err)

		_, err = list.Artifact(t.Context(), entry.SystemID, entry.Config)
		assert.ErrorContains(t, err, "the allowlist says")
	})

	t.Run("a path that is not there", func(t *testing.T) {
		entry := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
		entry.ArtifactPath = filepath.Join(t.TempDir(), "absent.bin")
		list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
		require.NoError(t, err)

		_, err = list.Artifact(t.Context(), entry.SystemID, entry.Config)
		assert.ErrorContains(t, err, "circuit artifact")
	})
}

// A system and a configuration together are a build, so two builds
// for one pair is a question with two answers. Refused at startup
// rather than resolved by order, which would verify against whichever
// the operator happened to write first.
func TestAllowlistRefusesTwoBuildsForOneSystemAndConfiguration(t *testing.T) {
	first := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
	second := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "another circuit")

	_, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{first, second}})
	assert.ErrorContains(t, err, "a second circuit is allowed for system")
}

// Both configurations may be allowed at once, which is what a
// deployment verifying ssc and psc needs.
func TestAllowlistTakesBothConfigurations(t *testing.T) {
	list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{
		entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "the ssc circuit"),
		entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingPSC, "the psc circuit"),
	}})
	require.NoError(t, err)
	assert.Len(t, list.Allowed(), 2)

	ssc, err := list.Artifact(t.Context(), nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC)
	require.NoError(t, err)
	psc, err := list.Artifact(t.Context(), nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingPSC)
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
		{"an unknown system", func(e *model.NymAuthCircuit) { e.SystemID = "urn:circuits:nobody:nym_auth:v1" }, "is not a nym_auth system_id"},
		{"no system at all", func(e *model.NymAuthCircuit) { e.SystemID = "" }, "no system_id"},
		{"a non-hex circuit id", func(e *model.NymAuthCircuit) { e.HashCircuitID = "not-hex" }, "hash_circuit_id is not hex"},
		{"one circuit id used twice", func(e *model.NymAuthCircuit) { e.SigCircuitID = e.HashCircuitID }, "the same, which no real build has"},
		{"no block_enc_hash", func(e *model.NymAuthCircuit) { e.BlockEncHash = 0 }, "block_enc_hash is zero"},
		{"no block_enc_sig", func(e *model.NymAuthCircuit) { e.BlockEncSig = 0 }, "block_enc_sig is zero"},
		{"a digest that is not a SHA-256", func(e *model.NymAuthCircuit) { e.ArtifactSHA256 = "abcd" }, "64-character hex SHA-256"},
		{"no declared length", func(e *model.NymAuthCircuit) { e.ArtifactBytes = 0 }, "must be positive"},
		{"neither a path nor an id", func(e *model.NymAuthCircuit) { e.ArtifactPath = "" }, "exactly one of artifact_path and artifact_id"},
		{"both a path and an id", func(e *model.NymAuthCircuit) { e.ArtifactID = "urn:circuits:x" }, "exactly one of artifact_path and artifact_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
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
	entry := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "a circuit")
	entry.ArtifactPath = ""
	entry.ArtifactID = "urn:circuits:longfellow:nym_auth:v1"

	_, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{entry}})
	assert.ErrorContains(t, err, "no verifier.nym_auth.circuits.sources are configured")

	list, err := NewAllowlist(model.NymAuthCircuits{
		Sources: []string{"https://zk-circuits.fly.dev"},
		Allow:   []model.NymAuthCircuit{entry},
	})
	require.NoError(t, err)

	_, err = list.Artifact(t.Context(), entry.SystemID, entry.Config)
	assert.ErrorContains(t, err, "cannot resolve yet")
}

// The point of keying on both: one verifier may allow Longfellow AND
// Vega for the same pseudonym configuration, which is what lets a
// wallet choose between the two systems a Verifier offers. Before the
// key had two parts this was a startup refusal.
func TestAllowlistTakesTwoProofSystemsForOneConfiguration(t *testing.T) {
	longfellow := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "the longfellow circuit")
	vega := entryFor(t, nymauth.SystemVegaNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "the vega circuit")

	list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{longfellow, vega}})
	require.NoError(t, err)
	assert.Equal(t, []string{
		nymauth.SystemLongfellowNymAuth + " " + nymauth.ConfigKnownOffenderMatchingSSC,
		nymauth.SystemVegaNymAuth + " " + nymauth.ConfigKnownOffenderMatchingSSC,
	}, list.Allowed())

	// Each resolves to ITS OWN artifact. One configuration, two
	// builds, and the system is the only thing telling them apart -
	// so a key that dropped it would serve one circuit's bytes to the
	// other system's verifier.
	fromLongfellow, err := list.Artifact(t.Context(), nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC)
	require.NoError(t, err)
	assert.Equal(t, "the longfellow circuit", string(fromLongfellow))

	fromVega, err := list.Artifact(t.Context(), nymauth.SystemVegaNymAuth, nymauth.ConfigKnownOffenderMatchingSSC)
	require.NoError(t, err)
	assert.Equal(t, "the vega circuit", string(fromVega))
}

// Allowing one system says nothing about the other. A presentation
// naming a system this verifier did not allow is an ordinary operator
// state, not a fault - and must not fall back to the system that IS
// allowed, which would check the proof with the wrong library.
func TestAllowlistDoesNotServeOneSystemForAnother(t *testing.T) {
	list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{
		entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "the longfellow circuit"),
	}})
	require.NoError(t, err)

	_, err = list.Entry(nymauth.SystemVegaNymAuth, nymauth.ConfigKnownOffenderMatchingSSC)
	assert.ErrorIs(t, err, ErrNoSuchCircuit)

	_, err = list.Artifact(t.Context(), nymauth.SystemVegaNymAuth, nymauth.ConfigKnownOffenderMatchingSSC)
	assert.ErrorIs(t, err, ErrNoSuchCircuit)
}

// Preload reads every local artifact, across systems as well as
// configurations - so a deployment allowing both and shipping only one
// of the two files fails at startup rather than at the first
// presentation that happens to pick the missing one.
func TestPreloadChecksEveryAllowedSystem(t *testing.T) {
	longfellow := entryFor(t, nymauth.SystemLongfellowNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "the longfellow circuit")
	vega := entryFor(t, nymauth.SystemVegaNymAuth, nymauth.ConfigKnownOffenderMatchingSSC, "the vega circuit")

	list, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{longfellow, vega}})
	require.NoError(t, err)
	require.NoError(t, list.Preload(t.Context()))

	// Now take away only the Vega artifact. Preload must notice: with
	// a one-part key the Vega entry would have replaced or been
	// replaced by the Longfellow one and only a single file would
	// ever have been read.
	require.NoError(t, os.Remove(vega.ArtifactPath))

	fresh, err := NewAllowlist(model.NymAuthCircuits{Allow: []model.NymAuthCircuit{longfellow, vega}})
	require.NoError(t, err)
	err = fresh.Preload(t.Context())
	require.Error(t, err)
	assert.ErrorContains(t, err, nymauth.SystemVegaNymAuth)
}
