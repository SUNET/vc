package openid4vci

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The wire members are the extension's: the examples below are taken from
// openid-4-verifiable-credential-issuance-auxiliary-data.md.
func TestAuxiliaryDataWireShape(t *testing.T) {
	psc := AuxiliaryDataEntry{
		Type: AuxiliaryDataTypeHashCommitment, Alg: "sha-256",
		Path: []string{"eu.europa.ec.eudi.nym_auth.1", "psc"}, Commitment: "JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0",
	}

	t.Run("a key proof carries auxiliary_data", func(t *testing.T) {
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"https://credential-issuer.example.com","iat":1792576000,
			"nonce":"LarRGSbmUPYtRYO6BQ4yn8","auxiliary_data":[{"type":"hash_commitment","alg":"sha-256",
			"path":["eu.europa.ec.eudi.nym_auth.1","psc"],"commitment":"JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0"}]}`))
		token := "eyJhbGciOiJFUzI1NiJ9." + payload + ".c2ln"

		fromJWT, err := ProofJWTToken(token).ExtractAuxiliaryData()
		require.NoError(t, err)
		assert.Equal(t, []AuxiliaryDataEntry{psc}, fromJWT)

		fromAttestation, err := ProofAttestation(token).ExtractAuxiliaryData()
		require.NoError(t, err)
		assert.Equal(t, []AuxiliaryDataEntry{psc}, fromAttestation)
	})

	t.Run("an entry of another type is ignored, and the proof stays valid", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256",
			"x":"nUWAoAv3XZith8E7i19OdaxOLYFOwM-Z2EuM02TirT4","y":"HskHU8BjUi1U9Xqi7Swmj8gwAK_0xkcDjEW_71SosEY"}}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"https://credential-issuer.example.com","iat":1792576000,
			"nonce":"LarRGSbmUPYtRYO6BQ4yn8","auxiliary_data":[{"type":"urn:example:future","alg":{"name":"x"},"path":["claims",0]}]}`))
		token := ProofJWTToken(header + "." + payload + ".c2ln")

		require.NoError(t, token.Validate())
		entries, err := token.ExtractAuxiliaryData()
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("an unreadable or repeated entry is refused", func(t *testing.T) {
		const entry = `{"type":"hash_commitment","alg":"sha-256","path":["eu.europa.ec.eudi.nym_auth.1","psc"],"commitment":"JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0"}`
		for rule, claim := range map[string]string{
			"auxiliary_data is an array":      entry,
			"an entry is an object":           `[5]`,
			"a hash_commitment entry decodes": `[{"type":"hash_commitment","path":"psc"}]`,
			"one entry per type and path":     `[` + entry + `,` + entry + `]`,
		} {
			_, err := decodeWalletAuxiliaryData(json.RawMessage(claim))
			assert.Error(t, err, rule)
		}
	})

	t.Run("a credential configuration announces auxiliary_data_supported", func(t *testing.T) {
		encoded, err := json.Marshal(CredentialConfigurationsSupported{
			Format: "mso_mdoc", Doctype: "eu.europa.ec.eudi.nym_auth.1",
			AuxiliaryDataSupported: &AuxiliaryDataSupported{
				ToWallet: []AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"}}},
				ToIssuer: []AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: []string{"eu.europa.ec.eudi.nym_auth.1", "psc"}}},
			},
		})
		require.NoError(t, err)
		assert.JSONEq(t, `{"format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.nym_auth.1",
			"auxiliary_data_supported": {
				"to_wallet": [{"type": "hash_commitment", "alg": "sha-256", "path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"]}],
				"to_issuer": [{"type": "hash_commitment", "alg": "sha-256", "path": ["eu.europa.ec.eudi.nym_auth.1", "psc"]}]}}`,
			string(encoded))
	})

	t.Run("a response carries auxiliary_data in credential_metadata", func(t *testing.T) {
		published := &CredentialMetadata{Display: []CredentialMetadataDisplay{{Name: "nym_auth"}}}
		response := &CredentialResponse{
			Credentials:        []Credential{{Credential: "ompuYW1lU3BhY2Vz..."}},
			CredentialMetadata: published,
		}
		response.AddAuxiliaryData(AuxiliaryDataEntry{
			Type: AuxiliaryDataTypeHashCommitment, Alg: "sha-256",
			Path: []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"}, Opening: "So-cHS4_SltsfY6fChssPQ",
		})

		encoded, err := json.Marshal(response)
		require.NoError(t, err)
		assert.JSONEq(t, `{"credentials": [{"credential": "ompuYW1lU3BhY2Vz..."}],
			"credential_metadata": {"display": [{"name": "nym_auth"}],
				"auxiliary_data": [{"type": "hash_commitment", "alg": "sha-256",
					"path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"], "opening": "So-cHS4_SltsfY6fChssPQ"}]}}`,
			string(encoded))
		assert.Empty(t, published.AuxiliaryData, "the published issuer metadata must not receive the opening")
	})
}
