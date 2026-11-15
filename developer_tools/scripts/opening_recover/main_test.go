package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A config without common or apigw is refused with an error, not a panic.
func TestAConfigWithoutCommonIsRefused(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("apigw: {}\n"), 0o600))

	code, err := run(t.Context(), []string{"-config", configPath, "-scope", "nym_auth", "-input", "x"}, io.Discard, io.Discard)
	require.Error(t, err)
	assert.Equal(t, exitError, code)
}

// Sources with different input counts cannot share one -input list, so
// -source selects the one to reproduce.
func TestSourceSelectsOneSourceScope(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret.key")
	require.NoError(t, os.WriteFile(secretPath, []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("s"), 32))), 0o600))
	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, fmt.Appendf(nil, `
common:
  credential_metadata:
    nym_auth:
      format: mso_mdoc
      auxiliary_data:
        to_wallet:
          - {type: hash_commitment, alg: sha-256, path: [eu.europa.ec.eudi.nym_auth.1, ssc]}
apigw:
  data_sources:
    presentation:
      scopes:
        nym_auth:
          from:
            pid:
              derivations:
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, ssc]
                    opening:
                      hkdf: {secret_path: %[1]q, inputs: [issuing_country, personal_administrative_number], bytes: 16}
            passport:
              derivations:
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, ssc]
                    opening:
                      hkdf: {secret_path: %[1]q, inputs: [issuing_country, document_type, document_number], bytes: 16}
`, secretPath), 0o600))
	const where = "apigw.data_sources.presentation.scopes.nym_auth.from."
	recoverOpening := func(args ...string) (int, string, error) {
		var out strings.Builder
		code, err := run(t.Context(), append([]string{"-config", configPath, "-scope", "nym_auth"}, args...), &out, io.Discard)
		return code, out.String(), err
	}

	code, out, err := recoverOpening("-source", where+"pid", "-input", "SE", "-input", "pan-100")
	require.NoError(t, err)
	assert.Equal(t, exitOK, code)
	assert.Contains(t, out, where+"pid")
	assert.NotContains(t, out, where+"passport")

	_, out, err = recoverOpening("-source", where+"passport", "-input", "SE", "-input", "P", "-input", "123")
	require.NoError(t, err)
	assert.Contains(t, out, where+"passport")

	_, _, err = recoverOpening("-input", "SE", "-input", "pan-100")
	require.Error(t, err, "one list does not fit both sources")
	assert.Contains(t, err.Error(), "-source")

	_, _, err = recoverOpening("-source", where+"absent", "-input", "SE", "-input", "pan-100")
	require.Error(t, err, "an unknown source scope is refused")
}

// The tool reproduces the commitment issuance writes, from the config and
// the identifiers, for every source scope that derives it.
func TestReproducesTheIssuedCommitment(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret.key")
	require.NoError(t, os.WriteFile(secretPath, []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("s"), 32))), 0o600))
	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, fmt.Appendf(nil, `
common:
  credential_metadata:
    nym_auth:
      format: mso_mdoc
      auxiliary_data:
        to_wallet:
          - {type: hash_commitment, alg: sha-256, path: [eu.europa.ec.eudi.nym_auth.1, ssc]}
    nym_auth_claim:
      format: mso_mdoc
      auxiliary_data:
        to_wallet:
          - {type: hash_commitment, alg: sha-256, path: [eu.europa.ec.eudi.nym_auth.1, ssc]}
apigw:
  data_sources:
    presentation:
      scopes:
        nym_auth:
          from:
            pid:
              derivations:
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, ssc]
                    opening:
                      hkdf: {secret_path: %[1]q, inputs: [issuing_country, personal_administrative_number], bytes: 16}
            pid_mdoc:
              derivations:
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, ssc]
                    opening:
                      hkdf: {secret_path: %[1]q, inputs: [eu.europa.ec.eudi.pid.1.issuing_country, eu.europa.ec.eudi.pid.1.administrative_number], bytes: 16}
        nym_auth_claim:
          from:
            pid:
              derivations:
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, ssc]
                    opening:
                      claim: {input: nym_auth_opening}
`, secretPath), 0o600))

	// What issuance writes for these source claims.
	cfg, err := loadConfig(t.Context(), configPath, io.Discard)
	require.NoError(t, err)
	issued := cfg.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"].Derivations
	hc := primitives.HashCommitmentFor(issued, claimpath.Keys("eu.europa.ec.eudi.nym_auth.1", "ssc"))
	opening, err := hc.NewOpening(map[string]any{"issuing_country": "SE", "personal_administrative_number": "pan-100"}, claimpath.Nested())
	require.NoError(t, err)
	commitment, err := openid4vci.HashCommitment(openid4vci.HashCommitmentAlgSHA256, opening)
	require.NoError(t, err)
	want := hex.EncodeToString(commitment)

	recoverOpening := func(args ...string) (int, string, error) {
		var out strings.Builder
		code, err := run(t.Context(), append([]string{"-config", configPath, "-scope", "nym_auth"}, args...), &out, io.Discard)
		return code, out.String(), err
	}

	code, out, err := recoverOpening("-input", "SE", "-input", "pan-100", "-expect", want)
	require.NoError(t, err)
	assert.Equal(t, exitOK, code, out)
	assert.Contains(t, out, "commitment: "+want)
	assert.Contains(t, out, "from.pid, apigw.data_sources.presentation.scopes.nym_auth.from.pid_mdoc", "both source scopes derive the same opening")

	code, out, err = recoverOpening("-input", "SE", "-input", "pan-101", "-expect", want)
	require.NoError(t, err)
	assert.Equal(t, exitMismatch, code, out)

	for rule, args := range map[string][]string{
		"-expect has a value":                   {"-input", "SE", "-input", "pan-100", "-expect", ""},
		"-expect has the alg's length":          {"-input", "SE", "-input", "pan-100", "-expect", "00"},
		"one value per hkdf input":              {"-input", "SE"},
		"-path names a to_wallet entry":         {"-input", "SE", "-input", "pan-100", "-path", `["eu.europa.ec.eudi.nym_auth.1","psc"]`},
		"a claim opening has nothing to derive": {"-scope", "nym_auth_claim", "-input", "SE"},
	} {
		code, _, err := recoverOpening(args...)
		assert.Error(t, err, rule)
		assert.Equal(t, exitError, code, rule)
	}
}
