package apiv1

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deliveringScope builds the configuration for one delivering scope,
// with or without the issuer's credential-encryption keys.
func deliveringScope(t *testing.T, withKeys bool) *Client {
	t.Helper()

	apigw := &model.APIGW{}
	if withKeys {
		apigw.IssuerMetadata.CredentialEncryption.Keys = []model.CredentialEncryptionKey{{}}
	}

	return &Client{
		log:         logger.NewSimple("test"),
		cfg:         &model.Cfg{Common: &model.Common{}, APIGW: apigw},
		seedSources: nil,
	}
}

func checkScope(t *testing.T, c *Client, namespaces []string) error {
	t.Helper()
	commitments := map[string]*model.CommitmentClaim{}
	for i, namespace := range namespaces {
		commitments[string(rune('a'+i))] = &model.CommitmentClaim{
			Seed: "primary", Subjects: []string{"id"}, Deliver: true, Namespace: namespace,
		}
	}
	return c.checkSeedAdvertisement("nym_auth", &model.CredentialMetadata{Commitments: commitments})
}

// An advertisement outside SPEC 2.6 section 5A.4's shape has to be
// refused at STARTUP.
//
// Issuance-time validation cannot help: a wallet treats a malformed
// entry as if the configuration were not offered, so it never sends a
// request there is anything to refuse. The operator would see a
// credential nobody asks for and no error anywhere.
func TestStartupRefusesAMalformedSeedAdvertisement(t *testing.T) {
	client := deliveringScope(t, true)

	t.Run("more namespaces than the advertisement carries", func(t *testing.T) {
		many := make([]string, maxSeedNamespaces+1)
		for i := range many {
			many[i] = "org.siros.ns" + string(rune('a'+i))
		}
		assert.ErrorContains(t, checkScope(t, client, many), "at most 8")
	})

	t.Run("a namespace longer than the wire allows", func(t *testing.T) {
		assert.ErrorContains(t, checkScope(t, client, []string{strings.Repeat("n", maxSeedNamespaceBytes+1)}), "at most 64")
	})

	t.Run("the reserved advertisement member as a namespace", func(t *testing.T) {
		// A response carrying it would be indistinguishable from an
		// issuer-metadata entry, and the specification calls each
		// malformed in the other's place.
		assert.ErrorContains(t, checkScope(t, client, []string{model.SeedNamespacesMember}), "reserved")
	})

	t.Run("a well-formed advertisement is accepted", func(t *testing.T) {
		require.NoError(t, checkScope(t, client, []string{"org.siros.nym_auth"}))
	})
}

// A delivering scope on an issuer with no credential-encryption keys
// is a deadlock, and startup is where it has to be said.
//
// checkResponseEncryption refuses a request carrying encryption
// parameters, because this issuer supports none; deliverSeeds refuses
// one that omits them. The credential is advertised and cannot be
// issued either way, and nothing at issuance can tell the operator
// why.
func TestStartupRefusesDeliveryWithoutEncryptionKeys(t *testing.T) {
	without := deliveringScope(t, false)
	err := checkScope(t, without, []string{"org.siros.nym_auth"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential_encryption.keys")

	with := deliveringScope(t, true)
	assert.NoError(t, checkScope(t, with, []string{"org.siros.nym_auth"}))
}

// A scope that does not deliver is unaffected by any of it.
func TestStartupIgnoresAScopeThatDeliversNothing(t *testing.T) {
	client := deliveringScope(t, false)
	meta := &model.CredentialMetadata{Commitments: map[string]*model.CommitmentClaim{
		"ssc": {Seed: "primary", Subjects: []string{"id"}},
	}}
	assert.NoError(t, client.checkSeedAdvertisement("nym_auth", meta))
}
