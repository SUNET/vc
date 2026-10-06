package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/require"
)

func formatCfg(scope, format string) *model.Cfg {
	return &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		scope: {Format: format, VCTM: &sdjwtvc.VCTM{VCT: "urn:example:" + scope}},
	}}}
}

// Issuer metadata put jwt_vc_json and jwt_vc_json-ld in its W3C branch,
// complete with the credential_definition Appendix A.1 requires, while
// handlers_issuer.go dispatches W3C issuance on ldp_vc and vc+ld+json only.
// A scope configured with either spelling was therefore advertised as
// issuable and failed with "unsupported or missing credential format" when
// a wallet actually asked for it.
func TestCheckIssuableCredentialFormats(t *testing.T) {
	for _, format := range []string{"jwt_vc_json", "jwt_vc_json-ld"} {
		t.Run(format+" is refused at config load", func(t *testing.T) {
			err := checkIssuableCredentialFormats(formatCfg("degree", format), "apigw")
			require.Error(t, err)
			require.Contains(t, err.Error(), "degree", "the error must name the scope to fix")
			require.Contains(t, err.Error(), format)
			require.Contains(t, err.Error(), "ldp_vc", "and point at the format that works")
		})
	}

	// The controls. Every format the issuer really dispatches has to keep
	// loading, or this check would be refusing working deployments.
	for _, format := range []string{"ldp_vc", "vc+ld+json", "dc+sd-jwt", "vc+sd-jwt", "mso_mdoc", "jwp"} {
		t.Run(format+" still loads", func(t *testing.T) {
			require.NoError(t, checkIssuableCredentialFormats(formatCfg("degree", format), "apigw"))
		})
	}

	t.Run("no common stanza is not an error", func(t *testing.T) {
		require.NoError(t, checkIssuableCredentialFormats(&model.Cfg{}, "apigw"))
	})

	t.Run("a nil constructor is left to checkCredentialMetadataEntries", func(t *testing.T) {
		require.NoError(t, checkIssuableCredentialFormats(&model.Cfg{
			Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{"degree": nil}},
		}, "apigw"))
	})

	// common.credential_metadata is shared, but it means different things to
	// different services: the apigw ISSUES these credentials, while the
	// verifier and the registry use the same stanza to describe credentials
	// somebody else issued. A verifier asking an external issuer for a
	// jwt_vc_json credential is exactly what #686 keeps working.
	for _, service := range []string{"verifier", "registry", "issuer"} {
		t.Run("an unissuable format is not the "+service+"'s problem", func(t *testing.T) {
			require.NoError(t, checkIssuableCredentialFormats(formatCfg("degree", "jwt_vc_json"), service))
		})
	}
}

// TestNew_RefusesAnUnissuableFormat drives the real loader, because the
// predicate test above cannot see WHERE the check is called - and a correct
// check that nothing calls is a check that does nothing. Removing the call
// from New() compiles and leaves every test above passing.
func TestNew_RefusesAnUnissuableFormat(t *testing.T) {
	dir := t.TempDir()

	// A local VCTM document, because the apigw loads credential schemas
	// before any of the checks below run: a bare vct would send it to the
	// credential registry and fail there instead, and the format check would
	// never be reached.
	vctm := filepath.Join(dir, "vctm.json")
	require.NoError(t, os.WriteFile(vctm, []byte(`{"vct":"urn:example:degree","name":"Degree"}`), 0o600))

	write := func(t *testing.T, name, format string) string {
		t.Helper()
		path := filepath.Join(dir, "config-"+name+".yaml")
		require.NoError(t, os.WriteFile(path, []byte(`
common:
  mongo:
    uri: mongodb://localhost:27017
  credential_metadata:
    degree:
      format: `+format+`
      vctm_file_path: `+vctm+`
`), 0o600))
		return path
	}

	t.Run("the apigw refuses jwt_vc_json", func(t *testing.T) {
		t.Setenv("VC_CONFIG_YAML", write(t, "apigw-jwt", "jwt_vc_json"))
		_, err := New(t.Context(), "apigw")
		require.Error(t, err)
		require.Contains(t, err.Error(), "jwt_vc_json")
		require.Contains(t, err.Error(), "degree", "the error must name the scope to fix")
	})

	// The control: an issuable format must get past this check. It may
	// still fail later on an incomplete stanza - what matters is that the
	// failure is not this one.
	t.Run("the apigw lets ldp_vc past", func(t *testing.T) {
		t.Setenv("VC_CONFIG_YAML", write(t, "apigw-ldp", "ldp_vc"))
		_, err := New(t.Context(), "apigw")
		if err != nil {
			require.NotContains(t, err.Error(), "cannot be issued by this build",
				"an issuable format must not be refused here")
		}
	})

	// The services that only READ such a credential must keep loading, or
	// this check would stop a verifier from asking an external issuer for a
	// jwt_vc_json credential - which #686 does not touch.
	for _, service := range []string{"verifier", "registry"} {
		t.Run("the "+service+" lets jwt_vc_json past", func(t *testing.T) {
			t.Setenv("VC_CONFIG_YAML", write(t, service+"-jwt", "jwt_vc_json"))
			_, err := New(t.Context(), service)
			if err != nil {
				require.NotContains(t, err.Error(), "cannot be issued by this build",
					"only the apigw issues these")
			}
		})
	}
}
