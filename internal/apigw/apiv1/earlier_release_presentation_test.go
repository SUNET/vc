package apiv1

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A presentation scope in the earlier release's spellings stores the
// verified claims of an mdoc as the earlier release stored them. From
// those, and from the verified claims a replica with the converted file
// stores, it builds the earlier release's document and opening. The
// expected values are the earlier release's (main at ff1df957) output on
// the same configuration and presentation.
func TestEarlierReleaseVerifiedClaimsCrossReplicas(t *testing.T) {
	const config = `common:
  credential_metadata:
    mdl:
      format: mso_mdoc
      mddl_file_path: %[1]s/mdl.mdoc.json
    nym_auth:
      format: mso_mdoc
      mddl_file_path: %[1]s/nym_auth.mdoc.json
      auxiliary_data:
        to_wallet:
          - {type: hash_commitment, alg: sha-256, path: [eu.europa.ec.eudi.nym_auth.1, ssc]}
apigw:
  data_sources:
    presentation:
      scopes:
        nym_auth:
          from:
            mdl:
              required_claims:
                birth_date: []
                family_name: [Svensson]
                org.iso.18013.5.1.given_name: []
                issuing_country: []
                administrative_number: []
              derivations:
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, ssc]
                    opening:
                      hkdf:
                        secret_path: %[2]s
                        inputs: [issuing_country, administrative_number]
                        bytes: 16
`
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.key")
	require.NoError(t, os.WriteFile(secret, []byte("c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M"), 0o600))
	metadata, err := filepath.Abs("../../../metadata")
	require.NoError(t, err)
	file := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(file, fmt.Appendf(nil, config, metadata, secret), 0o600))
	cfg, err := configuration.LoadFile(t.Context(), file, nil)
	require.NoError(t, err)
	c := &Client{cfg: cfg, log: logger.NewSimple("test")}
	pScope := cfg.APIGW.DataSources.Presentation.Scopes["nym_auth"]

	// The claims of an mDL as the presentation handler flattens them.
	presented := map[string]any{
		"org.iso.18013.5.1.birth_date": "1990-01-15", "birth_date": "1990-01-15",
		"org.iso.18013.5.1.family_name": "Svensson", "family_name": "Svensson",
		"org.iso.18013.5.1.given_name": "Anna", "given_name": "Anna",
		"org.iso.18013.5.1.issuing_country": "SE", "issuing_country": "SE",
		"org.iso.18013.5.1.administrative_number": "199001151234", "administrative_number": "199001151234",
		"docType": "org.iso.18013.5.1.mDL",
	}
	earlier := map[string]any{
		"administrative_number": "199001151234", "birth_date": "1990-01-15", "family_name": "Svensson",
		"issuing_country": "SE", "org.iso.18013.5.1.given_name": "Anna",
	}
	shapes, err := cfg.DerivationShapes(model.SourceScope{Source: model.DataSourcePresentation, Scope: "nym_auth", Presented: "mdl"})
	require.NoError(t, err)
	verified, err := verifiedClaims(shapes.Source, presented, pScope.From["mdl"].RequiredClaims)
	require.NoError(t, err)
	assert.Equal(t, earlier, verified, "verified claims")

	converted := map[string]any{
		"org.iso.18013.5.1.administrative_number": "199001151234", "org.iso.18013.5.1.birth_date": "1990-01-15",
		"org.iso.18013.5.1.family_name": "Svensson", "org.iso.18013.5.1.given_name": "Anna",
		"org.iso.18013.5.1.issuing_country": "SE",
	}
	for name, stored := range map[string]map[string]any{"the earlier release's": earlier, "a converted file's": converted} {
		authCtx := &cache.AuthorizationContext{SessionID: "s", VerifiedClaims: stored, PresentedScope: "mdl", DataSource: string(model.DataSourcePresentation)}
		document, err := c.buildPresentationDocument("nym_auth", pScope, authCtx, time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))
		require.NoError(t, err, name)
		assert.Equal(t, map[string]any{"birth_date": "1990-01-15"}, document, name)
		data, err := json.Marshal(document)
		require.NoError(t, err, name)
		_, toWallet, err := c.issueAuxiliaryData(t.Context(), "nym_auth", authCtx, nil, data, nil)
		require.NoError(t, err, name)
		require.Len(t, toWallet, 1, name)
		assert.Equal(t, "W--lqeKSAqwot__NrAYU_Q", toWallet[0].Opening, name)
	}
}
