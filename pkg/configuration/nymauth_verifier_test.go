package configuration

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/nymauth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nymAuthCfg(t *testing.T) *model.Cfg {
	t.Helper()
	const content = "a circuit"
	path := filepath.Join(t.TempDir(), "circuit.bin")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	sum := sha256.Sum256([]byte(content))

	return &model.Cfg{Verifier: &model.Verifier{NymAuth: model.NymAuthVerifier{
		Enable:     true,
		VerifierID: "verifier.example",
		Circuits: model.NymAuthCircuits{Allow: []model.NymAuthCircuit{{
			Config:         nymauth.ConfigKnownOffenderMatchingSSC,
			HashCircuitID:  "5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729",
			SigCircuitID:   "00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb",
			BlockEncHash:   6983,
			BlockEncSig:    4679,
			ArtifactPath:   path,
			ArtifactSHA256: hex.EncodeToString(sum[:]),
			ArtifactBytes:  int64(len(content)),
		}}},
	}}}
}

// Every one of these would otherwise surface as a REFUSED PROOF, with
// nothing pointing at the configuration.
func TestNymAuthVerifierConfigurationIsCheckedAtLoad(t *testing.T) {
	require.NoError(t, checkNymAuthVerifier(nymAuthCfg(t)), "the fixture must be valid")

	t.Run("a prefixed Client Identifier as the verifier_id", func(t *testing.T) {
		// Hashing it yields a pseudonym no other implementation
		// reports, so a comparison never matches and the subject
		// looks innocent.
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.VerifierID = "x509_san_dns:verifier.example"
		assert.ErrorContains(t, checkNymAuthVerifier(cfg), "verifier_id")
	})

	t.Run("a semantic verifier_id is accepted whole", func(t *testing.T) {
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.VerifierID = "semantic_id:VATSE-556000000101"
		assert.NoError(t, checkNymAuthVerifier(cfg))
	})

	t.Run("no verifier_id at all", func(t *testing.T) {
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.VerifierID = ""
		assert.Error(t, checkNymAuthVerifier(cfg))
	})

	t.Run("enabled with nothing allowed", func(t *testing.T) {
		// "On" and "cannot check a single proof" is not a state
		// anybody means to configure.
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.Circuits.Allow = nil
		assert.ErrorContains(t, checkNymAuthVerifier(cfg), "no proof could be verified")
	})

	t.Run("an allowlist that cannot be resolved", func(t *testing.T) {
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.Circuits.Allow[0].Config = "something-else"
		assert.ErrorContains(t, checkNymAuthVerifier(cfg), "known-offender-matching")
	})

	// The ARTIFACTS too, not only the entries describing them. An
	// entry can be well-formed and name a file that is not there, or
	// one whose digest moved when it was rebuilt, and both would
	// otherwise surface as a refused proof.
	t.Run("an artifact that is not there", func(t *testing.T) {
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.Circuits.Allow[0].ArtifactPath = filepath.Join(t.TempDir(), "absent.bin")
		assert.ErrorContains(t, checkNymAuthVerifier(cfg), "circuit artifact")
	})

	t.Run("an artifact whose digest moved", func(t *testing.T) {
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.Circuits.Allow[0].ArtifactSHA256 = hex.EncodeToString(make([]byte, sha256.Size))
		assert.ErrorContains(t, checkNymAuthVerifier(cfg), "hashes to")
	})

	t.Run("an artifact of the wrong length", func(t *testing.T) {
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.Circuits.Allow[0].ArtifactBytes++
		assert.ErrorContains(t, checkNymAuthVerifier(cfg), "the allowlist says")
	})
}

// A deployment with nym_auth OFF must start, whatever is left in the
// block - including a half-written allowlist entry.
//
// Struct-tag validation recurses into the subtree whether or not
// Enable is set, so a `required` tag on an entry field would stop a
// deployment that has the feature switched off. The entries are
// validated in NewAllowlist instead, which runs only when enabled.
func TestNymAuthVerifierDisabledWithAHalfWrittenEntryStillLoads(t *testing.T) {
	cfg := nymAuthCfg(t)
	cfg.Verifier.NymAuth.Enable = false
	cfg.Verifier.NymAuth.Circuits.Allow = []model.NymAuthCircuit{{Config: nymauth.ConfigKnownOffenderMatchingSSC}}

	require.NoError(t, checkNymAuthVerifier(cfg))

	// And through the ordinary validator, which is the path that
	// recursed into the subtree. The fixture is a bare Verifier so it
	// fails on its own required fields; what matters is that NONE of
	// the complaints is about nym_auth.
	err := helpers.Check(t.Context(), cfg, cfg, logger.NewSimple("test"))
	if err != nil {
		assert.NotContains(t, err.Error(), "nym_auth",
			"a disabled feature must not hold up startup over an entry nothing will read")
	}
}

// A deployment that does not verify pseudonym proofs is unaffected by
// any of it, including one that left a half-written block behind.
func TestNymAuthVerifierConfigurationIsSkippedWhenDisabled(t *testing.T) {
	assert.NoError(t, checkNymAuthVerifier(nil))
	assert.NoError(t, checkNymAuthVerifier(&model.Cfg{}))

	cfg := nymAuthCfg(t)
	cfg.Verifier.NymAuth.Enable = false
	cfg.Verifier.NymAuth.VerifierID = "x509_san_dns:verifier.example"
	assert.NoError(t, checkNymAuthVerifier(cfg))
}
