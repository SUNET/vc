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
			err := checkIssuableCredentialFormats(formatCfg("degree", format))
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
			require.NoError(t, checkIssuableCredentialFormats(formatCfg("degree", format)))
		})
	}

	t.Run("no common stanza is not an error", func(t *testing.T) {
		require.NoError(t, checkIssuableCredentialFormats(&model.Cfg{}))
	})

	t.Run("a nil constructor is left to checkCredentialMetadataEntries", func(t *testing.T) {
		require.NoError(t, checkIssuableCredentialFormats(&model.Cfg{
			Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{"degree": nil}},
		}))
	})
}

// TestNew_RefusesAnUnissuableFormat drives the real loader, because the
// predicate test above cannot see WHERE the check is called - and a correct
// check that nothing calls is a check that does nothing. Removing the call
// from New() compiles and leaves every test above passing.
func TestNew_RefusesAnUnissuableFormat(t *testing.T) {
	dir := t.TempDir()
	write := func(t *testing.T, format string) string {
		t.Helper()
		path := filepath.Join(dir, "config-"+format+".yaml")
		require.NoError(t, os.WriteFile(path, []byte(`
common:
  mongo:
    uri: mongodb://localhost:27017
  credential_metadata:
    degree:
      format: `+format+`
      # A vct, so the struct validator (which runs first) is satisfied and
      # the format check is actually reached.
      vct: urn:example:degree
`), 0o600))
		return path
	}

	t.Run("jwt_vc_json is refused", func(t *testing.T) {
		t.Setenv("VC_CONFIG_YAML", write(t, "jwt_vc_json"))
		_, err := New(t.Context(), "registry")
		require.Error(t, err)
		require.Contains(t, err.Error(), "jwt_vc_json")
		require.Contains(t, err.Error(), "degree", "the error must name the scope to fix")
	})

	// The control: an issuable format must get past this check. It may
	// still fail later on an incomplete registry stanza - what matters is
	// that the failure is not this one.
	t.Run("ldp_vc gets past this check", func(t *testing.T) {
		t.Setenv("VC_CONFIG_YAML", write(t, "ldp_vc"))
		_, err := New(t.Context(), "registry")
		if err != nil {
			require.NotContains(t, err.Error(), "cannot be issued by this build",
				"an issuable format must not be refused here")
		}
	})
}
