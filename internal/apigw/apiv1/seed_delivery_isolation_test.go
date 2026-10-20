package apiv1

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deliveringClient is an issuer that both advertises a seed namespace
// and echoes credential_metadata on the response - the combination the
// delivery path has to keep apart.
func deliveringClient(t *testing.T) *Client {
	t.Helper()

	emitMetadata := true
	claim := &model.CommitmentClaim{Seed: "primary", Subjects: []string{"id"}, Deliver: true}
	metadata := &openid4vci.CredentialIssuerMetadataParameters{
		CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
			"nym_auth": {},
		},
	}
	client := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{
			Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
				"nym_auth": {Commitments: map[string]*model.CommitmentClaim{"ssc": claim}},
			}},
			APIGW: &model.APIGW{Delivery: model.APIGWDelivery{
				EmitCredentialMetadataOnResponse: &emitMetadata,
			}},
		},
		issuerMetadata: metadata,
	}
	require.NoError(t, client.advertiseSeedNamespaces())
	return client
}

// advertisement returns what the issuer metadata currently publishes
// under the seed member.
func advertisement(t *testing.T, client *Client) string {
	t.Helper()
	config := client.issuerMetadata.CredentialConfigurationsSupported["nym_auth"]
	require.NotNil(t, config.CredentialMetadata)
	raw, ok := config.CredentialMetadata.Extensions[model.SeedMetadataMember]
	require.True(t, ok, "the advertisement must still be published")
	return string(raw)
}

// Delivering a seed must not touch the PUBLISHED issuer metadata.
//
// Both the advertisement and the delivered seed travel under the same
// member name, org.siros.secret_seed - names in the metadata, values on
// the response. With emit_credential_metadata_on_response set, the
// response's credential_metadata came straight from the issuer metadata
// map, so writing the delivery into it overwrote the advertisement with
// a subject's secret. The published /.well-known document then serves
// that seed, and the specification calls an advertisement carrying a
// value malformed - which takes the configuration out of service as
// well as leaking it.
func TestDeliveringASeedLeavesTheAdvertisementAlone(t *testing.T) {
	client := deliveringClient(t)
	before := advertisement(t, client)
	require.Contains(t, before, model.SeedNamespacesMember)

	const secret = "0123456789abcdef0123456789abcdef"
	response := client.newCredentialResponse(nil, "nym_auth", "nym_auth")
	require.NoError(t, client.deliverSeeds(response,
		map[string]string{model.DefaultSeedNamespace: secret},
		&openid4vci.CredentialResponseEncryption{}))

	// The response carries the seed...
	delivered, ok := response.CredentialMetadata.Extensions[model.SeedMetadataMember]
	require.True(t, ok)
	assert.Contains(t, string(delivered), secret)

	// ...and the issuer metadata still carries the advertisement.
	after := advertisement(t, client)
	assert.Equal(t, before, after, "delivery must not rewrite the published advertisement")
	assert.NotContains(t, after, secret, "a subject's seed must never reach the issuer metadata")
}

// Two issuances must not see each other's seed. Sharing the metadata
// object made the last writer win, so one subject could be handed
// another's.
func TestConcurrentDeliveriesDoNotShareMetadata(t *testing.T) {
	client := deliveringClient(t)

	seeds := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	responses := make([]*openid4vci.CredentialResponse, len(seeds))

	var wg sync.WaitGroup
	for i, secret := range seeds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := client.newCredentialResponse(nil, "nym_auth", "nym_auth")
			if err := client.deliverSeeds(response,
				map[string]string{model.DefaultSeedNamespace: secret},
				&openid4vci.CredentialResponseEncryption{}); err != nil {
				t.Error(err)
				return
			}
			responses[i] = response
		}()
	}
	wg.Wait()

	for i, secret := range seeds {
		require.NotNil(t, responses[i])
		raw := string(responses[i].CredentialMetadata.Extensions[model.SeedMetadataMember])
		assert.Containsf(t, raw, secret, "response %d must carry its own seed", i)
		for j, other := range seeds {
			if i == j {
				continue
			}
			assert.NotContainsf(t, raw, other, "response %d must not carry response %d's seed", i, j)
		}
	}

	assert.NotContains(t, advertisement(t, client), "aaaa")
}

// The member the response carries is the seeds map and nothing else -
// no namespace list smuggled in from the advertisement it was copied
// from.
func TestDeliveredMemberCarriesOnlyTheSeeds(t *testing.T) {
	client := deliveringClient(t)

	response := client.newCredentialResponse(nil, "nym_auth", "nym_auth")
	require.NoError(t, client.deliverSeeds(response,
		map[string]string{model.DefaultSeedNamespace: "0123456789abcdef0123456789abcdef"},
		&openid4vci.CredentialResponseEncryption{}))

	var member map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(response.CredentialMetadata.Extensions[model.SeedMetadataMember], &member))
	_, hasNamespaces := member[model.SeedNamespacesMember]
	assert.False(t, hasNamespaces, "%q is reserved for the advertisement", model.SeedNamespacesMember)
	assert.Len(t, member, 1)
	for namespace := range member {
		assert.False(t, strings.Contains(namespace, " "))
	}
}
