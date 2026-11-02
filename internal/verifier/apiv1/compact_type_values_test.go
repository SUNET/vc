package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	compactTestVC = "https://www.w3.org/2018/credentials#VerifiableCredential"
	compactTestID = "https://schemas.accredify.io/idvc/vocab/v1/vocab#IndividualIDCredential"
)

func w3cTestDCQL() *openid4vp.DCQL {
	return &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
		ID:     "individualIdvc",
		Format: openid4vp.FormatLdpVCDCQL,
		Meta:   openid4vp.MetaQuery{TypeValues: [][]string{{compactTestVC, compactTestID}}},
	}}}
}

// signedTypeValues returns the type_values the wallet would read from a signed request object.
func signedTypeValues(t *testing.T, signedJWT string) [][]string {
	t.Helper()
	parts := strings.Split(signedJWT, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		DCQLQuery openid4vp.DCQL `json:"dcql_query"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Len(t, claims.DCQLQuery.Credentials, 1)
	return claims.DCQLQuery.Credentials[0].Meta.TypeValues
}

func enableCompactTypeValues(client *Client) {
	if client.cfg.Common == nil {
		client.cfg.Common = &model.Common{}
	}
	client.cfg.Common.OpenID4VPCompat.CompactW3CTypeValues = new(true)
}

// By default the wallet is sent what OpenID4VP 1.0 B.3.2 defines: expanded IRIs.
func TestCreateRequestObject_TypeValuesAreExpandedByDefault(t *testing.T) {
	client := newSigningTestClient(t)

	signed, err := client.CreateRequestObject(t.Context(), "session-expanded", w3cTestDCQL(), "nonce", nil)
	require.NoError(t, err)

	assert.Equal(t, [][]string{{compactTestVC, compactTestID}}, signedTypeValues(t, signed))
}

// With the switch on, the wallet is sent compact terms - and nothing the verifier itself
// reads back changes: the cached request object, which the response check matches
// against, stays expanded.
func TestCreateRequestObject_CompactTypeValuesOnlyChangeWhatTheWalletIsSent(t *testing.T) {
	client := newSigningTestClient(t)
	enableCompactTypeValues(client)

	signed, err := client.CreateRequestObject(t.Context(), "session-compact", w3cTestDCQL(), "nonce", nil)
	require.NoError(t, err)

	assert.Equal(t, [][]string{{"VerifiableCredential", "IndividualIDCredential"}}, signedTypeValues(t, signed))

	cached, err := client.GetRequestObject(t.Context(), "session-compact")
	require.NoError(t, err)
	assert.Equal(t, [][]string{{compactTestVC, compactTestID}}, cached.DCQLQuery.Credentials[0].Meta.TypeValues,
		"the response check reads the cached query, which must keep the expanded types")
	assert.True(t, openid4vp.MatchTypeValues([]string{compactTestVC, compactTestID}, cached.DCQLQuery.Credentials[0].Meta.TypeValues),
		"an expanded credential must still satisfy the query")
}

// The request object the wallet fetches from the QR / request_uri path is signed in a second place.
func TestVerificationRequestObject_CompactTypeValues(t *testing.T) {
	client := newSigningTestClient(t)
	enableCompactTypeValues(client)

	_, err := client.CreateRequestObject(t.Context(), "session-verif", w3cTestDCQL(), "nonce", nil)
	require.NoError(t, err)

	signed, err := client.VerificationRequestObject(t.Context(), &VerificationRequestObjectRequest{ID: "session-verif"})
	require.NoError(t, err)

	assert.Equal(t, [][]string{{"VerifiableCredential", "IndividualIDCredential"}}, signedTypeValues(t, signed))
}
