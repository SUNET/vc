package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockCredentialSubject = []byte(`{
  "id": "did:example:subject",
  "familyName": "Doe",
  "givenName": "John",
  "birthDate": "1990-01-15"
}`)

func TestMakeVC20_ECDSA2019(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	req := &CreateVC20Request{
		Scope:           "pid",
		DocumentData:    mockCredentialSubject,
		CredentialTypes: []string{"VerifiableCredential", "PersonIdentificationData"},
		SubjectDID:      "did:example:subject",
		Cryptosuite:     openid4vp.CryptosuiteECDSA2019,
	}

	reply, err := client.MakeVC20(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, reply)
	assert.NotEmpty(t, reply.Credential)
	assert.NotEmpty(t, reply.CredentialID)
	assert.NotEmpty(t, reply.ValidFrom)

	// Verify it's valid JSON-LD
	var cred map[string]any
	err = json.Unmarshal(reply.Credential, &cred)
	require.NoError(t, err)

	// Check required fields
	assert.Contains(t, cred, "@context")
	assert.Contains(t, cred, "type")
	assert.Contains(t, cred, "issuer")
	assert.Contains(t, cred, "credentialSubject")
	assert.Contains(t, cred, "proof")

	// Check proof
	proof, ok := cred["proof"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "DataIntegrityProof", proof["type"])
	assert.Equal(t, "ecdsa-rdfc-2019", proof["cryptosuite"])
	assert.NotEmpty(t, proof["proofValue"])

	t.Logf("Created VC20 credential: %s", string(reply.Credential))
}

func TestMakeVC20_ECDSASD2023(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	req := &CreateVC20Request{
		Scope:           "pid",
		DocumentData:    mockCredentialSubject,
		CredentialTypes: []string{"VerifiableCredential", "PersonIdentificationData"},
		SubjectDID:      "did:example:subject",
		Cryptosuite:     openid4vp.CryptosuiteECDSASd,
		MandatoryPointers: []string{
			"/issuer",
		},
	}

	reply, err := client.MakeVC20(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, reply)
	assert.NotEmpty(t, reply.Credential)

	// Verify it's valid JSON-LD
	var cred map[string]any
	err = json.Unmarshal(reply.Credential, &cred)
	require.NoError(t, err)

	// Check proof
	proof, ok := cred["proof"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "DataIntegrityProof", proof["type"])
	assert.Equal(t, "ecdsa-sd-2023", proof["cryptosuite"])
	assert.NotEmpty(t, proof["proofValue"])

	t.Logf("Created VC20 SD credential: %s", string(reply.Credential))
}

func TestMakeVC20_DefaultCryptosuite(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	req := &CreateVC20Request{
		Scope:           "pid",
		DocumentData:    mockCredentialSubject,
		CredentialTypes: []string{"VerifiableCredential"},
		// No cryptosuite specified - should default to ecdsa-rdfc-2019
	}

	reply, err := client.MakeVC20(ctx, req)
	require.NoError(t, err)

	// Verify it uses the default cryptosuite
	var cred map[string]any
	err = json.Unmarshal(reply.Credential, &cred)
	require.NoError(t, err)

	proof, ok := cred["proof"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ecdsa-rdfc-2019", proof["cryptosuite"])
}

func TestMakeVC20_InvalidCryptosuite(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	req := &CreateVC20Request{
		Scope:           "pid",
		DocumentData:    mockCredentialSubject,
		CredentialTypes: []string{"VerifiableCredential"},
		Cryptosuite:     "invalid-cryptosuite",
	}

	_, err := client.MakeVC20(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported cryptosuite")
}

func TestMakeVC20_InvalidDocumentData(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	req := &CreateVC20Request{
		Scope:           "pid",
		DocumentData:    []byte(`{invalid json`),
		CredentialTypes: []string{"VerifiableCredential"},
		Cryptosuite:     openid4vp.CryptosuiteECDSA2019,
	}

	_, err := client.MakeVC20(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse document data")
}

func TestMakeVC20_RoundTrip(t *testing.T) {
	ctx := t.Context()
	log := logger.NewSimple("test")
	client := mockNewClient(ctx, t, "ecdsa", log)

	req := &CreateVC20Request{
		Scope:           "pid",
		DocumentData:    mockCredentialSubject,
		CredentialTypes: []string{"VerifiableCredential", "PersonIdentificationData"},
		SubjectDID:      "did:example:subject",
		Cryptosuite:     openid4vp.CryptosuiteECDSA2019,
	}

	// Create credential
	createReply, err := client.MakeVC20(ctx, req)
	require.NoError(t, err)

	// Create a VC20 handler for verification
	handler, err := openid4vp.NewVC20Handler(
		openid4vp.WithVC20StaticKey(client.signer.PublicKey()),
	)
	require.NoError(t, err)

	// Verify the credential
	result, err := handler.VerifyAndExtract(ctx, string(createReply.Credential))
	require.NoError(t, err)

	assert.Equal(t, "https://test-issuer.sunet.se", result.Issuer)
	assert.Equal(t, "did:example:subject", result.Subject)
	assert.Contains(t, result.Types, "VerifiableCredential")
	assert.Contains(t, result.Types, "PersonIdentificationData")
}
