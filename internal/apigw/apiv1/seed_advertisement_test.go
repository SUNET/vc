package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func advertisingClient(t *testing.T, claim *model.CommitmentClaim, offered bool) *Client {
	t.Helper()
	metadata := &openid4vci.CredentialIssuerMetadataParameters{
		CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{},
	}
	if offered {
		metadata.CredentialConfigurationsSupported["nym_auth"] = openid4vci.CredentialConfigurationsSupported{}
	}
	return &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {Commitments: map[string]*model.CommitmentClaim{"ssc": claim}},
		}}},
		issuerMetadata: metadata,
	}
}

// The advertisement carries namespace NAMES and never a value.
//
// It and the issuance-time refusal are one mechanism: the
// specification encrypts a response only when the wallet asked, so a
// wallet that cannot see in advance that a seed is coming has no reason
// to request encryption and would be refused at issuance with nothing
// to tell it why.
func TestSeedNamespacesAreAdvertisedByNameOnly(t *testing.T) {
	c := advertisingClient(t, &model.CommitmentClaim{
		Seed: "primary", Subjects: []string{"pan"}, Deliver: true,
	}, true)
	require.NoError(t, c.advertiseSeedNamespaces())

	config := c.issuerMetadata.CredentialConfigurationsSupported["nym_auth"]
	require.NotNil(t, config.CredentialMetadata,
		"the map holds values, so an advertisement written into a copy would never be published")

	encoded, err := json.Marshal(config.CredentialMetadata)
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"org.siros.secret_seed":{"namespaces":["org.siros.nym_auth"]}}`,
		string(encoded),
		"names only, and the default namespace when the claim names none")

	// The shape the specification calls malformed in this position.
	assert.NotContains(t, string(encoded), `"org.siros.nym_auth":"`,
		"an issuer-metadata entry carrying a hexadecimal seed is malformed, and a wallet then treats the configuration as not offered")
}

// A configured namespace wins over the default, and duplicates collapse.
func TestAdvertisementUsesTheConfiguredNamespace(t *testing.T) {
	c := advertisingClient(t, &model.CommitmentClaim{
		Seed: "primary", Subjects: []string{"pan"}, Deliver: true, Namespace: "org.example.other",
	}, true)
	require.NoError(t, c.advertiseSeedNamespaces())

	encoded, err := json.Marshal(c.issuerMetadata.CredentialConfigurationsSupported["nym_auth"].CredentialMetadata)
	require.NoError(t, err)
	assert.JSONEq(t, `{"org.siros.secret_seed":{"namespaces":["org.example.other"]}}`, string(encoded))
}

// A claim that does not deliver is not advertised, so a deployment
// using only commitments is untouched.
func TestNoAdvertisementWithoutDelivery(t *testing.T) {
	c := advertisingClient(t, &model.CommitmentClaim{Seed: "primary", Subjects: []string{"pan"}}, true)
	require.NoError(t, c.advertiseSeedNamespaces())

	config := c.issuerMetadata.CredentialConfigurationsSupported["nym_auth"]
	assert.Nil(t, config.CredentialMetadata, "nothing to advertise, nothing added")
}

// A scope that delivers a seed but is not offered is refused at
// startup. The configuration says this credential hands out a permanent
// per-subject secret; an operator should learn it is unreachable now
// rather than from its absence later.
func TestUnofferedDeliveringScopeRefusesAtStartup(t *testing.T) {
	c := advertisingClient(t, &model.CommitmentClaim{
		Seed: "primary", Subjects: []string{"pan"}, Deliver: true,
	}, false)
	err := c.advertiseSeedNamespaces()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an offered credential configuration")
}
