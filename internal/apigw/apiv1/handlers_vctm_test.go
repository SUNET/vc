package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/require"
)

func newOfferTestClient(t *testing.T, credMeta map[string]*model.CredentialMetadata) *Client {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	return &Client{
		log: log,
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: credMeta,
			},
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{
						IssuerURL: "https://issuer.example.com",
						Wallets: map[string]model.CredentialOfferWallets{
							"local": {RedirectURI: "https://wallet.example.com/cb"},
						},
					},
				},
			},
		},
	}
}

func TestSVGTemplateReply_NilRequest(t *testing.T) {
	client := &Client{}
	_, err := client.SVGTemplateReply(t.Context(), nil)
	require.Error(t, err)
}

func TestSVGTemplateReply_BothVCTMAndMDDLSet(t *testing.T) {
	client := &Client{}
	_, err := client.SVGTemplateReply(t.Context(), &SVGTemplateRequest{
		VCTM: &sdjwtvc.VCTM{},
		MDDL: &mdoc.MDDLSchema{},
	})
	require.Error(t, err)
}

func TestSVGTemplateReply_NeitherVCTMNorMDDLSet(t *testing.T) {
	client := &Client{}
	_, err := client.SVGTemplateReply(t.Context(), &SVGTemplateRequest{})
	require.Error(t, err)
}

func TestUICreateCredentialOffer_VCTMScope(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client := newOfferTestClient(t, credMeta)

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope:    "siros_id",
		WalletID: "local",
	})
	require.NoError(t, err)
	require.Equal(t, "SIROS ID", reply.Name)
	require.Equal(t, "urn:siros:id", reply.ID)
}

// Regression test for the bug this PR fixes: mso_mdoc scopes have no VCTM
// by design (GetVCTMFromScope returns ErrScopeIsMDoc) - UICreateCredentialOffer
// must fall back to the MDDL schema instead of propagating that error, since
// mdoc issuance itself works fine via GetMDDLFromScope.
func TestUICreateCredentialOffer_MDocScope(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"mdl": {MDDL: &mdoc.MDDLSchema{
			DocType: "org.iso.18013.5.1.mDL",
			Display: []mdoc.DisplayProperties{
				{Locale: "en-US", Name: "Mobile Driving Licence"},
			},
		}},
	}
	client := newOfferTestClient(t, credMeta)

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope:    "mdl",
		WalletID: "local",
	})
	require.NoError(t, err)
	require.Equal(t, "Mobile Driving Licence", reply.Name)
	require.Equal(t, "org.iso.18013.5.1.mDL", reply.ID)
}

func TestUICreateCredentialOffer_MDocScopeWithoutDisplay(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"mdl": {MDDL: &mdoc.MDDLSchema{DocType: "org.iso.18013.5.1.mDL"}},
	}
	client := newOfferTestClient(t, credMeta)

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope:    "mdl",
		WalletID: "local",
	})
	require.NoError(t, err)
	require.Equal(t, "org.iso.18013.5.1.mDL", reply.Name, "should fall back to DocType when no Display entries")
	require.Equal(t, "org.iso.18013.5.1.mDL", reply.ID)
}

func TestUICreateCredentialOffer_UnknownScope(t *testing.T) {
	client := newOfferTestClient(t, map[string]*model.CredentialMetadata{})

	_, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope:    "nonexistent",
		WalletID: "local",
	})
	require.Error(t, err)
}

func TestUICreateCredentialOffer_InvalidWalletID(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client := newOfferTestClient(t, credMeta)

	_, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope:    "siros_id",
		WalletID: "does-not-exist",
	})
	require.Error(t, err)
}
