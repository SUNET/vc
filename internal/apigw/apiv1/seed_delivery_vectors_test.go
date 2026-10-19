package apiv1

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// privatedataVectorsSHA256 pins test-vectors/vectors.jsonl from
// sirosfoundation/privatedata-spec at main 8c4c865 (SPEC 2.6).
//
// These vectors are written for the WALLET, and that is exactly why
// they are worth testing the issuer against: every case the wallet
// refuses is a response this issuer must never emit, and the accept
// cases are the shape it must emit. Pinned so that a local edit cannot
// quietly relax what we are being held to.
const privatedataVectorsSHA256 = "2893c0c68da7735ef17da110405161c2f81d09d9faebc1340f00218c4e3f9ec4"

type deliveredSecretVector struct {
	ID     string `json:"id"`
	Inputs struct {
		Cases []struct {
			Name                string          `json:"name"`
			JWEEncrypted        *bool           `json:"jweEncrypted"`
			CommitmentNamespace string          `json:"commitmentNamespace"`
			SSCHex              string          `json:"sscHex"`
			Deferred            bool            `json:"deferred"`
			Response            json.RawMessage `json:"response"`
			// Raw, because the shape differs between vector files
			// (an object here, a bare string elsewhere) and this test
			// drives the issuer from the RESPONSE, not from the
			// wallet-side outcome.
			Expected json.RawMessage `json:"expected"`
		} `json:"cases"`
	} `json:"inputs"`
}

func loadDeliveredSecretVectors(t *testing.T) map[string]deliveredSecretVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/privatedata-vectors.jsonl")
	require.NoError(t, err)

	sum := sha256.Sum256(raw)
	require.Equal(t, privatedataVectorsSHA256, hex.EncodeToString(sum[:]),
		"the vendored vectors differ from privatedata-spec main; re-vendor rather than edit")

	out := map[string]deliveredSecretVector{}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var v deliveredSecretVector
		require.NoError(t, json.Unmarshal(line, &v))
		if strings.HasPrefix(v.ID, "delivered-secret-") {
			out[v.ID] = v
		}
	}
	require.NoError(t, scanner.Err())
	require.Contains(t, out, "delivered-secret-wire-001")
	return out
}

// What this issuer emits must be what the wallet's accept vectors
// describe - the same member, in the same place, with the same shape.
func TestDeliveredSeedMatchesTheAcceptVectors(t *testing.T) {
	vectors := loadDeliveredSecretVectors(t)
	wire := vectors["delivered-secret-wire-001"]
	require.NotEmpty(t, wire.Inputs.Cases)

	encryption := &openid4vci.CredentialResponseEncryption{}
	checked := 0

	for _, tc := range wire.Inputs.Cases {
		var expected struct {
			CredentialMetadata map[string]json.RawMessage `json:"credential_metadata"`
			NotificationID     string                     `json:"notification_id"`
		}
		require.NoError(t, json.Unmarshal(tc.Response, &expected))

		member, ok := expected.CredentialMetadata[model.SeedMetadataMember]
		if !ok {
			continue
		}
		var seeds map[string]string
		require.NoError(t, json.Unmarshal(member, &seeds))

		t.Run(tc.Name, func(t *testing.T) {
			response := &openid4vci.CredentialResponse{
				Credentials: []openid4vci.Credential{{Credential: "eyJ.cred0"}},
			}
			require.NoError(t, deliveryClient().deliverSeeds(response, seeds, encryption))

			// The member, where the vector puts it: at the TOP level of
			// credential_metadata, not nested in a display entry.
			encoded, err := json.Marshal(response.CredentialMetadata)
			require.NoError(t, err)
			var got map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(encoded, &got))
			require.Contains(t, got, model.SeedMetadataMember)
			assert.JSONEq(t, string(member), string(got[model.SeedMetadataMember]))

			assert.NotEmpty(t, response.NotificationID,
				"the specification requires a notification_id with a delivered seed; it is how a failed commitment check is reported")
			checked++
		})
	}
	assert.Positive(t, checked, "no accept case carried a seed; this test is not looking at anything")
}

// Every response shape the wallet refuses is one this issuer must never
// produce. The two it can produce are the ones tested here; the rest
// are wallet-side or structurally unreachable, and named below.
func TestIssuerCannotProduceTheRefusedShapes(t *testing.T) {
	vectors := loadDeliveredSecretVectors(t)
	require.Contains(t, vectors, "delivered-secret-refusal-001")

	seeds := map[string]string{model.DefaultSeedNamespace: "00112233445566778899aabbccddeeff"}

	t.Run("plain (unencrypted) response carrying a seed", func(t *testing.T) {
		response := &openid4vci.CredentialResponse{Credentials: []openid4vci.Credential{{Credential: "eyJ.cred0"}}}
		err := deliveryClient().deliverSeeds(response, seeds, nil)
		require.Error(t, err, "a permanent per-subject secret must not go out in the clear")
		assert.Contains(t, err.Error(), "credential_response_encryption")
		assert.Nil(t, response.CredentialMetadata, "and nothing may be attached on the way to refusing")
	})

	t.Run("no notification_id", func(t *testing.T) {
		response := &openid4vci.CredentialResponse{Credentials: []openid4vci.Credential{{Credential: "eyJ.cred0"}}}
		require.NoError(t, deliveryClient().deliverSeeds(response, seeds, &openid4vci.CredentialResponseEncryption{}))
		assert.NotEmpty(t, response.NotificationID,
			"the issuer mints one rather than emitting a response the wallet must refuse")
	})

	t.Run("the designated namespace cannot be absent from what we emit", func(t *testing.T) {
		response := &openid4vci.CredentialResponse{Credentials: []openid4vci.Credential{{Credential: "eyJ.cred0"}}}
		require.NoError(t, deliveryClient().deliverSeeds(response, seeds, &openid4vci.CredentialResponseEncryption{}))
		encoded, err := json.Marshal(response.CredentialMetadata)
		require.NoError(t, err)
		assert.Contains(t, string(encoded), model.DefaultSeedNamespace)
	})

	t.Run("credential_metadata is always an object", func(t *testing.T) {
		response := &openid4vci.CredentialResponse{Credentials: []openid4vci.Credential{{Credential: "eyJ.cred0"}}}
		require.NoError(t, deliveryClient().deliverSeeds(response, seeds, &openid4vci.CredentialResponseEncryption{}))
		encoded, err := json.Marshal(response.CredentialMetadata)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(strings.TrimSpace(string(encoded)), "{"),
			"an array here is malformed; the type can only encode an object, and this pins that")
	})

	// "commitment mismatch" is the WALLET's check: it compares
	// SHA256(seed) against the credential's ssc. The issuer cannot
	// produce a mismatch without a bug in seed derivation itself, which
	// is covered where the derivation lives.
	//
	// "deferred credential response carrying a seed" is structurally
	// unreachable here: VCIDeferredCredential answers 501 and returns
	// no Credential Response at all, so there is nothing to attach a
	// seed to. Asserted rather than assumed.
	t.Run("the deferred endpoint cannot carry a seed", func(t *testing.T) {
		response, err := deliveryClient().VCIDeferredCredential(t.Context(), &openid4vci.DeferredCredentialRequest{TransactionID: "t-1"})
		require.NoError(t, err)
		require.Nil(t, response,
			"deferred issuance returns no Credential Response at all, so there is nothing for a seed to ride on; "+
				"the HTTP layer turns this into a 501. If this ever returns a response, seed delivery needs an explicit refusal here.")
	})
}

// A malformed seed or namespace is refused before it reaches a wallet.
func TestMalformedSeedsAreRefused(t *testing.T) {
	encryption := &openid4vci.CredentialResponseEncryption{}

	for _, tc := range []struct {
		name  string
		seeds map[string]string
	}{
		{"uppercase hexadecimal", map[string]string{model.DefaultSeedNamespace: "00112233445566778899AABBCCDDEEFF"}},
		{"too short", map[string]string{model.DefaultSeedNamespace: "00112233445566778899aabbccddee"}},
		{"too long", map[string]string{model.DefaultSeedNamespace: "00112233445566778899aabbccddeeff00"}},
		{"not hexadecimal", map[string]string{model.DefaultSeedNamespace: "zz112233445566778899aabbccddeeff"}},
		{"empty namespace", map[string]string{"": "00112233445566778899aabbccddeeff"}},
		{"the reserved advertisement member", map[string]string{model.SeedNamespacesMember: "00112233445566778899aabbccddeeff"}},
		{"namespace over 64 bytes", map[string]string{strings.Repeat("n", 65): "00112233445566778899aabbccddeeff"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &openid4vci.CredentialResponse{Credentials: []openid4vci.Credential{{Credential: "eyJ.cred0"}}}
			err := deliveryClient().deliverSeeds(response, tc.seeds, encryption)
			require.Error(t, err)
			for _, value := range tc.seeds {
				assert.NotContains(t, err.Error(), value,
					"the error must never carry the seed; it is the secret")
			}
		})
	}

	t.Run("more namespaces than the wire shape allows", func(t *testing.T) {
		seeds := map[string]string{}
		for i := range maxSeedNamespaces + 1 {
			seeds[string(rune('a'+i))] = "00112233445566778899aabbccddeeff"
		}
		response := &openid4vci.CredentialResponse{Credentials: []openid4vci.Credential{{Credential: "eyJ.cred0"}}}
		assert.Error(t, deliveryClient().deliverSeeds(response, seeds, encryption))
	})
}

// deliveryClient is a Client with just enough wired for the delivery
// helpers: they touch no store, no cache and no gRPC client.
func deliveryClient() *Client { return &Client{log: logger.NewSimple("test")} }
