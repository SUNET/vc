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

	return &model.Cfg{Verifier: &model.Verifier{
		// A PDP is part of a valid nym_auth configuration, not an
		// extra: the issuer key comes from the holder's own chain,
		// so without one there is nothing that says the key belongs
		// to a real issuer.
		Trust: model.TrustConfig{PDPURL: "https://pdp.example/access/v1/evaluation"},
		NymAuth: model.NymAuthVerifier{
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

	t.Run("a prefixed Client Identifier is the verifier_id", func(t *testing.T) {
		// Accepted under v0.4: the verifier_id is hashed exactly as
		// published, prefix included, and the archive's reference
		// pseudonyms are computed from that form. This was refused
		// until 2026-10-20, when the rule reversed.
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.VerifierID = "x509_san_dns:verifier.example"
		assert.NoError(t, checkNymAuthVerifier(cfg))
	})

	t.Run("a prefix with no identifier after it", func(t *testing.T) {
		// Names no Verifier, so it is refused - the one thing the
		// reversal did not change.
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.VerifierID = "x509_san_dns:"
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

	t.Run("enabled with no PDP", func(t *testing.T) {
		// NewTrustEvaluatorFromConfig returns AllowAllEvaluator for
		// an empty pdp_url, and it answers Trusted=true to every
		// question. For nym_auth that means a chain the HOLDER
		// minted is accepted as a trusted issuer - so the holder
		// picks its own issuer key and therefore its own pseudonym,
		// and a flagged person presents a value that matches nothing.
		cfg := nymAuthCfg(t)
		cfg.Verifier.Trust.PDPURL = ""
		assert.ErrorContains(t, checkNymAuthVerifier(cfg), "pdp_url")
		assert.ErrorContains(t, checkNymAuthVerifier(cfg), "holder's own certificate chain")
	})

	t.Run("enabled with nothing allowed", func(t *testing.T) {
		// "On" and "cannot check a single proof" is not a state
		// anybody means to configure.
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.Circuits.Allow = nil
		assert.ErrorContains(t, checkNymAuthVerifier(cfg), "no proof could be verified")
	})

	t.Run("a source that is not an http(s) URL", func(t *testing.T) {
		// Still refused when the feature is ON. Moving the check out
		// of the struct tag must not mean losing it.
		for _, bad := range []string{"", "not-a-url", "ftp://catalog.example", "https://"} {
			cfg := nymAuthCfg(t)
			cfg.Verifier.NymAuth.Circuits.Sources = []string{bad}
			assert.ErrorContains(t, checkNymAuthVerifier(cfg), "sources[0]",
				"source %q must be refused when nym_auth is enabled", bad)
		}

		// And a good one is accepted, so this refuses bad values
		// rather than the field.
		cfg := nymAuthCfg(t)
		cfg.Verifier.NymAuth.Circuits.Sources = []string{"https://zk-circuits.fly.dev"}
		assert.NoError(t, checkNymAuthVerifier(cfg))
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
	t.Run("a Ligero parameter left out", func(t *testing.T) {
		// Zero is not a default here: the loader compares both
		// against its allowed build and refuses - after reading and
		// hashing the artifact - with a status code that says "bad
		// circuit" and not "you left a number out".
		for _, tc := range []struct {
			name   string
			mutate func(*model.NymAuthCircuit)
			want   string
		}{
			{"block_enc_hash", func(e *model.NymAuthCircuit) { e.BlockEncHash = 0 }, "block_enc_hash is zero"},
			{"block_enc_sig", func(e *model.NymAuthCircuit) { e.BlockEncSig = 0 }, "block_enc_sig is zero"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cfg := nymAuthCfg(t)
				tc.mutate(&cfg.Verifier.NymAuth.Circuits.Allow[0])
				assert.ErrorContains(t, checkNymAuthVerifier(cfg), tc.want)
			})
		}
	})

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
	// A half-written SOURCE too, not only a half-written entry: the
	// sources list carried an `httpurl` struct tag, which recursed
	// the same way and stopped a disabled deployment over a URL
	// nothing would fetch.
	cfg.Verifier.NymAuth.Circuits.Sources = []string{"", "not-a-url"}

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
