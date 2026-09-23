package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/require"
)

// memCredentialOfferStore is an in-memory db.CredentialOfferStore, so that
// the by-reference QR rendering (which persists the offer under a UUID) can
// be exercised without Mongo/SQL.
type memCredentialOfferStore struct {
	docs    map[string]*db.CredentialOfferDocument
	saves   int
	saveErr error
}

func newMemCredentialOfferStore() *memCredentialOfferStore {
	return &memCredentialOfferStore{docs: map[string]*db.CredentialOfferDocument{}}
}

func (m *memCredentialOfferStore) Save(_ context.Context, doc *db.CredentialOfferDocument) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	// uuid is uniquely indexed in both real implementations, so an insert
	// over an existing id is an error there too.
	if _, ok := m.docs[doc.UUID]; ok {
		return errors.New("duplicate key")
	}
	m.saves++
	m.docs[doc.UUID] = doc
	return nil
}

func (m *memCredentialOfferStore) Get(_ context.Context, uuid string) (*db.CredentialOfferDocument, error) {
	doc, ok := m.docs[uuid]
	if !ok {
		return nil, errors.New("not found")
	}
	return doc, nil
}

func (m *memCredentialOfferStore) Delete(_ context.Context, uuid string) error {
	delete(m.docs, uuid)
	return nil
}

func newOfferTestClient(t *testing.T, credMeta map[string]*model.CredentialMetadata) *Client {
	t.Helper()
	client, _ := newOfferTestClientWithStore(t, credMeta)
	return client
}

func newOfferTestClientWithStore(t *testing.T, credMeta map[string]*model.CredentialMetadata) (*Client, *memCredentialOfferStore) {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	store := newMemCredentialOfferStore()

	return &Client{
		log:                  log,
		credentialOfferStore: store,
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: credMeta,
			},
			APIGW: &model.APIGW{
				// Deliberately NOT the same as the issuer identifier below:
				// the by-reference endpoint is served by this gateway, and
				// OpenID4VCI does not require the two to coincide.
				PublicURL: "https://apigw.example.com",
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{
						IssuerURL: "https://issuer.example.com",
						Wallets: map[string]model.CredentialOfferWallets{
							"local": {Label: "Local Wallet", RedirectURI: "https://wallet.example.com/cb"},
						},
					},
				},
			},
		},
	}, store
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

// TestSVGTemplateReply_MDDLDataURI exercises the MDDL branch's happy path
// with a data: URI (avoids a real cacheService/HTTP origin) - the MDDL
// branch previously had no test coverage at all.
func TestSVGTemplateReply_MDDLDataURI(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client := &Client{
		log:          log,
		cacheService: &cache.Service{SVGTemplate: cache.NewTestMemoryCache[string](time.Minute)},
	}
	mddl := &mdoc.MDDLSchema{
		Display: []mdoc.DisplayProperties{
			{
				Rendering: &mdoc.Rendering{
					SVGTemplates: []mdoc.SVGTemplate{
						{URI: "data:image/svg+xml;base64,PHN2Zy8+"},
					},
				},
			},
		},
	}

	reply, err := client.SVGTemplateReply(t.Context(), &SVGTemplateRequest{MDDL: mddl})
	require.NoError(t, err)
	require.Equal(t, "PHN2Zy8+", reply.Template)
}

// TestSVGTemplateReply_MDDLNoTemplates confirms the MDDL branch's own
// no-templates error path, mirroring the existing VCTM coverage's shape.
func TestSVGTemplateReply_MDDLNoTemplates(t *testing.T) {
	client := &Client{}
	_, err := client.SVGTemplateReply(t.Context(), &SVGTemplateRequest{MDDL: &mdoc.MDDLSchema{}})
	require.Error(t, err)
}

func TestUICreateCredentialOffer_VCTMScope(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client := newOfferTestClient(t, credMeta)

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope: "siros_id",
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
		Scope: "mdl",
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
		Scope: "mdl",
	})
	require.NoError(t, err)
	require.Equal(t, "org.iso.18013.5.1.mDL", reply.Name, "should fall back to DocType when no Display entries")
	require.Equal(t, "org.iso.18013.5.1.mDL", reply.ID)
}

func TestUICreateCredentialOffer_UnknownScope(t *testing.T) {
	client := newOfferTestClient(t, map[string]*model.CredentialMetadata{})

	_, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope: "nonexistent",
	})
	require.Error(t, err)
}

// The offer is wallet-independent: the opaque, authority-less
// openid-credential-offer:// URI is now the default rendering rather than
// something a reserved wallet_id had to opt into.
func TestUICreateCredentialOffer_OpaqueByValueURI(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client := newOfferTestClient(t, credMeta)

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope: "siros_id",
	})
	require.NoError(t, err)
	require.Equal(t, "SIROS ID", reply.Name)
	require.Equal(t, "urn:siros:id", reply.ID)
	require.True(t, strings.HasPrefix(reply.URI, "openid-credential-offer://?"), "URI must be authority-less opaque form, got %q", reply.URI)

	params, err := openid4vci.ParseCredentialOfferURI(reply.URI)
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com", params.CredentialIssuer)
	require.Equal(t, []string{"siros_id"}, params.CredentialConfigurationIDs)
}

// Offer is the bare query string, and it is the same one embedded in every
// other rendering - the DC API issuance request is built from it client-side.
func TestUICreateCredentialOffer_OfferQueryString(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client := newOfferTestClient(t, credMeta)

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope: "siros_id",
	})
	require.NoError(t, err)
	require.NotEmpty(t, reply.Offer)
	require.Equal(t, "openid-credential-offer://?"+reply.Offer, reply.URI)

	values, err := url.ParseQuery(reply.Offer)
	require.NoError(t, err)
	require.JSONEq(t,
		`{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["siros_id"],"grants":{"authorization_code":{}}}`,
		values.Get("credential_offer"),
	)
}

// Every configured wallet gets the same offer behind its own redirect_uri.
func TestUICreateCredentialOffer_PerWalletURIs(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client := newOfferTestClient(t, credMeta)

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope: "siros_id",
	})
	require.NoError(t, err)
	require.Len(t, reply.Wallets, 1)

	wallet, ok := reply.Wallets["local"]
	require.True(t, ok, "configured wallet must be present in the reply")
	require.Equal(t, "Local Wallet", wallet.Name)
	require.Equal(t, "https://wallet.example.com/cb?"+reply.Offer, wallet.URI)
}

// Wallets is always an object, never null, so the front-end schema can
// require it without special-casing a deployment with no wallets configured.
func TestUICreateCredentialOffer_NoWalletsConfigured(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client := newOfferTestClient(t, credMeta)
	client.cfg.APIGW.Delivery.CredentialOffers.Wallets = nil

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope: "siros_id",
	})
	require.NoError(t, err)
	require.NotNil(t, reply.Wallets)
	require.Empty(t, reply.Wallets)

	encoded, err := json.Marshal(reply)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"wallets":{}`)
}

// The QR is the one rendering where offer size matters, so it carries the
// offer by reference. The referenced UUID must actually resolve through the
// same store GET /credential-offer/:credential_offer_uuid reads from.
func TestUICreateCredentialOffer_QRIsByReference(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client, store := newOfferTestClientWithStore(t, credMeta)

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{
		Scope: "siros_id",
	})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(reply.QR.URI, "openid-credential-offer://?credential_offer_uri="), "QR must carry the offer by reference, got %q", reply.QR.URI)
	require.NotContains(t, reply.QR.URI, "credential_offer=")
	require.NotEmpty(t, reply.QR.Base64Image)

	values, err := url.ParseQuery(strings.TrimPrefix(reply.QR.URI, "openid-credential-offer://?"))
	require.NoError(t, err)

	offerURI := openid4vci.CredentialOfferURI(values.Get("credential_offer_uri"))
	// Rooted at the gateway that actually serves /credential-offer/, NOT at
	// the issuer identifier - those are different fields and a deployment may
	// legally differ in both.
	require.True(t, strings.HasPrefix(offerURI.String(), "https://apigw.example.com/credential-offer/"), "offer URI must point at the gateway's by-reference endpoint, got %q", offerURI.String())
	require.NotContains(t, offerURI.String(), "issuer.example.com")

	uuid, err := offerURI.UUID()
	require.NoError(t, err)

	doc, err := store.Get(t.Context(), uuid)
	require.NoError(t, err, "the referenced offer must have been persisted")
	require.Equal(t, "https://issuer.example.com", doc.CredentialOfferParameters.CredentialIssuer)
	require.Equal(t, []string{"siros_id"}, doc.CredentialOfferParameters.CredentialConfigurationIDs)
}

// The by-reference QR is only useful if it points at something that serves
// it. That is APIGW.PublicURL, not CredentialOffers.IssuerURL - the latter
// is the issuer IDENTIFIER, which OpenID4VCI never requires the offer to be
// retrievable from. Building the URL from the identifier would hand out a
// credential_offer_uri that 404s wherever the two differ, and it would do so
// silently, since the QR itself still scans.
func TestUICreateCredentialOffer_ReferenceURIUsesGatewayOrigin(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client, store := newOfferTestClientWithStore(t, credMeta)
	require.NotEqual(t, client.cfg.APIGW.PublicURL, client.cfg.APIGW.Delivery.CredentialOffers.IssuerURL,
		"this test is only meaningful while the two origins differ")

	reply, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{Scope: "siros_id"})
	require.NoError(t, err)

	values, err := url.ParseQuery(strings.TrimPrefix(reply.QR.URI, "openid-credential-offer://?"))
	require.NoError(t, err)
	offerURI := openid4vci.CredentialOfferURI(values.Get("credential_offer_uri"))
	require.True(t, strings.HasPrefix(offerURI.String(), client.cfg.APIGW.PublicURL+"/credential-offer/"),
		"offer URI must be rooted at the gateway origin, got %q", offerURI.String())

	// The identifier still travels inside the offer, where it belongs.
	uuid, err := offerURI.UUID()
	require.NoError(t, err)
	doc, err := store.Get(t.Context(), uuid)
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com", doc.CredentialOfferParameters.CredentialIssuer)
}

// Without a public origin there is nowhere to point the reference at, so the
// request must fail rather than emit a QR that cannot be resolved.
func TestUICreateCredentialOffer_NoPublicURLRefuses(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client, _ := newOfferTestClientWithStore(t, credMeta)
	client.cfg.APIGW.PublicURL = ""

	_, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{Scope: "siros_id"})
	require.Error(t, err)
}

// GET /offers/:scope is unauthenticated, so a by-reference id generated
// fresh per request would let anyone grow the credential-offer collection
// without limit by asking for one valid scope in a loop. The id is derived
// from the offer instead, so repeated requests reuse one stored document:
// the collection is bounded by how many distinct offers the issuer can
// produce, not by how many requests arrive.
func TestUICreateCredentialOffer_StoredOffersAreBounded(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client, store := newOfferTestClientWithStore(t, credMeta)

	first, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{Scope: "siros_id"})
	require.NoError(t, err)

	for range 50 {
		next, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{Scope: "siros_id"})
		require.NoError(t, err)
		require.Equal(t, first.QR.URI, next.QR.URI, "the same offer must map to the same by-reference URI")
		require.Equal(t, first.Offer, next.Offer)
	}

	require.Len(t, store.docs, 1, "51 requests for one scope must leave exactly one stored offer")
	require.Equal(t, 1, store.saves, "the document must be written once, not rewritten per request")
}

// Bounded, but not collapsed: two different scopes are two different offers
// and must not share a document.
func TestUICreateCredentialOffer_DistinctScopesDistinctReferences(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
		"ehic":     {VCTM: &sdjwtvc.VCTM{Name: "EHIC", VCT: "urn:siros:ehic"}},
	}
	client, store := newOfferTestClientWithStore(t, credMeta)

	first, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{Scope: "siros_id"})
	require.NoError(t, err)
	second, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{Scope: "ehic"})
	require.NoError(t, err)

	require.NotEqual(t, first.QR.URI, second.QR.URI)
	require.Len(t, store.docs, 2)
}

// A store that cannot persist the offer must fail the request rather than
// hand out a by-reference QR that will 404 when scanned.
func TestUICreateCredentialOffer_StoreFailure(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"siros_id": {VCTM: &sdjwtvc.VCTM{Name: "SIROS ID", VCT: "urn:siros:id"}},
	}
	client, store := newOfferTestClientWithStore(t, credMeta)
	store.saveErr = errors.New("mongo is down")

	_, err := client.UICreateCredentialOffer(t.Context(), &UICredentialOfferRequest{Scope: "siros_id"})
	require.Error(t, err)
}

func TestUICreateCredentialOffer_MDocScopeOpaqueURI(t *testing.T) {
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
		Scope: "mdl",
	})
	require.NoError(t, err)
	require.Equal(t, "Mobile Driving Licence", reply.Name)
	require.Equal(t, "org.iso.18013.5.1.mDL", reply.ID)
	require.True(t, strings.HasPrefix(reply.URI, "openid-credential-offer://?"), "URI must be authority-less opaque form, got %q", reply.URI)
}
