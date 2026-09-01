package model

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadedRegistrationCertificate_IssuerInfo covers the issuer-side
// rendering of the same document VerifierInfo renders for a verifier.
func TestLoadedRegistrationCertificate_IssuerInfo(t *testing.T) {
	loaded := &LoadedRegistrationCertificate{JWT: "header.payload.signature", Format: "rc-wrp+jwt"}

	info := loaded.IssuerInfo()
	require.Len(t, info, 1)
	assert.Equal(t, "rc-wrp+jwt", info[0].Format)
	assert.Equal(t, "header.payload.signature", info[0].Data)

	// Same document, same shape, whichever direction it travels.
	vi := loaded.VerifierInfo()
	require.Len(t, vi, 1)
	assert.Equal(t, vi[0].Format, info[0].Format)
	assert.Equal(t, vi[0].Data, info[0].Data)
}

func TestLoadedRegistrationCertificate_IssuerInfo_Absent(t *testing.T) {
	var nilLoaded *LoadedRegistrationCertificate
	assert.Nil(t, nilLoaded.IssuerInfo())
	assert.Nil(t, (&LoadedRegistrationCertificate{Format: "rc-wrp+jwt"}).IssuerInfo(),
		"no JWT means nothing to advertise")
}

// TestIssuerMetadata_IssuerInfoOmittedWhenUnconfigured pins that a deployment
// outside an ARF trust framework sees no change: issuer_info must be absent
// from the JSON, not present and empty.
func TestIssuerMetadata_IssuerInfoOmittedWhenUnconfigured(t *testing.T) {
	md := &openid4vci.CredentialIssuerMetadataParameters{CredentialIssuer: "https://issuer.example"}

	raw, err := json.Marshal(md)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.NotContains(t, got, "issuer_info")
}

// TestIssuerMetadata_IssuerInfoReachesSignedMetadata is the property that
// matters to a wallet: signed_metadata is built by marshalling this struct,
// so a field that did not round-trip would be advertised unsigned only.
func TestIssuerMetadata_IssuerInfoReachesSignedMetadata(t *testing.T) {
	md := &openid4vci.CredentialIssuerMetadataParameters{
		CredentialIssuer: "https://issuer.example",
		IssuerInfo: []openid4vci.IssuerInfo{
			{Format: "rc-wrp+jwt", Data: "header.payload.signature"},
		},
	}

	claims, err := md.MarshalJWTClaims()
	require.NoError(t, err)

	entries, ok := claims["issuer_info"].([]any)
	require.True(t, ok, "issuer_info must appear in the signed metadata claims")
	require.Len(t, entries, 1)

	entry, ok := entries[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "rc-wrp+jwt", entry["format"])
	assert.Equal(t, "header.payload.signature", entry["data"])

	// credential_ids is a verifier_info concept and has no issuer analogue.
	assert.NotContains(t, entry, "credential_ids")
}
