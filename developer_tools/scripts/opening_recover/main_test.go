package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
`, secretPath), 0o600))

	// What issuance writes for these source claims.
	cfg, err := loadConfig(configPath)
	require.NoError(t, err)
	issued := cfg.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"].Derivations
	opening, err := primitives.HashCommitmentFor(issued, claimpath.Keys("eu.europa.ec.eudi.nym_auth.1", "ssc")).
		NewOpening(map[string]any{"issuing_country": "SE", "personal_administrative_number": "pan-100"})
	require.NoError(t, err)
	commitment, err := openid4vci.HashCommitment(openid4vci.HashCommitmentAlgSHA256, opening)
	require.NoError(t, err)
	want := hex.EncodeToString(commitment)

	recoverOpening := func(args ...string) (int, string, error) {
		var out strings.Builder
		code, err := run(t.Context(), append([]string{"-config", configPath, "-scope", "nym_auth"}, args...), &out)
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
		"-expect has a value":           {"-input", "SE", "-input", "pan-100", "-expect", ""},
		"one value per hkdf input":      {"-input", "SE"},
		"-path names a to_wallet entry": {"-input", "SE", "-input", "pan-100", "-path", `["eu.europa.ec.eudi.nym_auth.1","psc"]`},
	} {
		code, _, err := recoverOpening(args...)
		assert.Error(t, err, rule)
		assert.Equal(t, exitError, code, rule)
	}
}
