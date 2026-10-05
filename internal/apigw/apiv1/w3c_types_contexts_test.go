package apiv1

import (
	"context"
	"testing"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// TestW3CTypesAndContextsComeFromOneScope: CredentialConfigurationsSupported
// is keyed by SCOPE, the configuration id comes from the request and the scope
// comes from the token - so reading types from the named configuration and
// contexts from the authorised scope paired two different scopes.
//
// A caller authorised for A naming configuration B got B's types with A's
// contexts: terms those contexts do not define, which expand to relative IRIs
// and match no query a verifier builds from B's credential_type_values. The
// credential is issued, looks right, and can never be presented - which is the
// "these three fields only work as a set" failure, reached through the request
// rather than through the configuration file.
func TestW3CTypesAndContextsComeFromOneScope(t *testing.T) {
	client := &Client{
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"diploma": {
				Format:             "ldp_vc",
				CredentialTypes:    []string{"VerifiableCredential", "DiplomaCredential"},
				CredentialContexts: []string{"https://example.org/diploma"},
			},
			"licence": {
				Format:             "ldp_vc",
				CredentialTypes:    []string{"VerifiableCredential", "LicenceCredential"},
				CredentialContexts: []string{"https://example.org/licence"},
			},
		}}},
		issuerMetadata: &openid4vci.CredentialIssuerMetadataParameters{
			CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
				"diploma": {CredentialDefinition: &openid4vci.CredentialDefinition{
					Type: []string{"VerifiableCredential", "DiplomaCredential"},
				}},
				"licence": {CredentialDefinition: &openid4vci.CredentialDefinition{
					Type: []string{"VerifiableCredential", "LicenceCredential"},
				}},
			},
		},
	}

	t.Run("a configuration naming another scope takes that scope's contexts too", func(t *testing.T) {
		types, contexts, _ := client.w3cTypesAndContexts("diploma", "licence")
		require.Contains(t, types, "LicenceCredential")
		require.Equal(t, []string{"https://example.org/licence"}, contexts,
			"the contexts must define the types, so both come from the configuration that was named")
		require.NotContains(t, contexts, "https://example.org/diploma")
	})

	t.Run("no configuration id uses the authorised scope for both", func(t *testing.T) {
		types, contexts, _ := client.w3cTypesAndContexts("diploma", "")
		require.Contains(t, types, "DiplomaCredential")
		require.Equal(t, []string{"https://example.org/diploma"}, contexts)
	})

	t.Run("an unknown configuration id falls back to the authorised scope", func(t *testing.T) {
		types, contexts, _ := client.w3cTypesAndContexts("diploma", "no-such-configuration")
		require.Contains(t, types, "DiplomaCredential")
		require.Equal(t, []string{"https://example.org/diploma"}, contexts)
	})
}

// recordingVC20Issuer captures the MakeVC20 request the APIGW builds. Every
// other method is left to the embedded nil interface, so an unexpected call
// panics rather than returning a silent zero value.
type recordingVC20Issuer struct {
	apiv1_issuer.IssuerServiceClient
	got *apiv1_issuer.MakeVC20Request
}

func (r *recordingVC20Issuer) MakeVC20(_ context.Context, in *apiv1_issuer.MakeVC20Request, _ ...grpc.CallOption) (*apiv1_issuer.MakeVC20Reply, error) {
	r.got = in
	return &apiv1_issuer.MakeVC20Reply{Credential: []byte("{}"), CredentialId: "urn:uuid:test"}, nil
}

// TestIssueVC20UsesTheResolvedConfiguration pins the WIRING, which the
// resolver's own tests cannot see.
//
// ResolveCredentialConfigurationID can be perfectly correct and still never
// reach the issuance path - issueVC20 used to read
// req.CredentialConfigurationID directly, which is empty whenever the wallet
// authorised by credential_identifier. The credential was then built from
// whichever scope matchScope happened to pick, with that scope's types,
// contexts and cryptosuite, while the identifier had selected another.
//
// So this asserts on what reaches the issuer, with a request that names NO
// configuration id at all - exactly the shape the bug needed.
func TestIssueVC20UsesTheResolvedConfiguration(t *testing.T) {
	issuer := &recordingVC20Issuer{}
	client := &Client{
		log:          logger.NewSimple("test"),
		issuerClient: issuer,
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"diploma": {
				Format:             "ldp_vc",
				CredentialTypes:    []string{"VerifiableCredential", "DiplomaCredential"},
				CredentialContexts: []string{"https://example.org/diploma"},
			},
			"licence": {
				Format:             "ldp_vc",
				CredentialTypes:    []string{"VerifiableCredential", "LicenceCredential"},
				CredentialContexts: []string{"https://example.org/licence"},
			},
		}}},
		issuerMetadata: &openid4vci.CredentialIssuerMetadataParameters{
			CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
				"licence": {
					Cryptosuite: "eddsa-rdfc-2022",
					CredentialDefinition: &openid4vci.CredentialDefinition{
						Type: []string{"VerifiableCredential", "LicenceCredential"},
					},
				},
			},
		},
	}

	// The authorised scope is "diploma"; the identifier selected "licence",
	// and the request carries no credential_configuration_id.
	_, err := client.issueVC20(t.Context(), "diploma", []byte(`{}`), "person-1", "licence",
		&openid4vci.CredentialRequest{
			CredentialIdentifier: "licence-1",
			Proof:                &openid4vci.Proof{ProofType: "jwt"},
		})
	require.NoError(t, err)
	require.NotNil(t, issuer.got, "the issuer was never called")

	require.Equal(t, []string{"VerifiableCredential", "LicenceCredential"}, issuer.got.CredentialTypes,
		"the types must come from the configuration the identifier selected, not the authorised scope")
	require.Equal(t, "eddsa-rdfc-2022", issuer.got.Cryptosuite,
		"and so must the cryptosuite")
	require.Contains(t, issuer.got.AdditionalContexts, "https://example.org/licence",
		"and the contexts, or the types expand to relative IRIs no verifier can match")
}
