package apiv2

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEnv provides a pre-configured test environment with store, client, and context.
type testEnv struct {
	store  *mockDatastoreV2Store
	client *Client
	ctx    context.Context
}

func setupTestEnv() *testEnv {
	store := newMockStore()
	return &testEnv{
		store:  store,
		client: newTestClient(store),
		ctx:    context.Background(),
	}
}

// createMapping is a test helper that creates an identity mapping and asserts success.
func (e *testEnv) createMapping(t *testing.T, source, identifier string, attrs map[string]string) string {
	t.Helper()
	reply, err := e.client.CreateIdentityMapping(e.ctx, &CreateIdentityMappingRequest{
		AuthenticSource: source,
		Identifier:      identifier,
		Attributes:      attrs,
	})
	require.NoError(t, err)
	return reply.Identifier
}

// uploadDoc is a test helper that uploads a document and asserts success.
func (e *testEnv) uploadDoc(t *testing.T, source, scope, docID string, identities []string, data map[string]any) string {
	t.Helper()
	reply, err := e.client.UploadDocument(e.ctx, &UploadDocumentRequest{
		Meta:         &model.V2MetaData{AuthenticSource: source, Scope: scope, DocumentID: docID},
		Identities:   identities,
		DocumentData: data,
	})
	require.NoError(t, err)
	return reply.DocumentID
}

// TestFullLifecycle tests the complete workflow: create mapping → upload doc → resolve → get → delete.
func TestFullLifecycle(t *testing.T) {
	env := setupTestEnv()

	// Step 1: Create identity mapping
	id := env.createMapping(t, "EHIC_DB", "id-lifecycle-001", map[string]string{"ssn": "199001011234", "nationality": "SE"})
	assert.Equal(t, "id-lifecycle-001", id)

	// Step 2: Upload document linked to the identifier
	validFrom := int64(1700000000)
	validTo := int64(1800000000)
	_, err := env.client.UploadDocument(env.ctx, &UploadDocumentRequest{
		Meta: &model.V2MetaData{
			AuthenticSource:     "EHIC_DB",
			Scope:               "ehic",
			DocumentID:          "doc-lifecycle-001",
			CredentialValidFrom: &validFrom,
			CredentialValidTo:   &validTo,
		},
		Identities:   []string{"id-lifecycle-001"},
		DocumentData: map[string]any{"card_number": "SE-EHIC-12345", "institution": "Försäkringskassan"},
	})
	require.NoError(t, err)

	// Step 3: Resolve identity → get documents (single-step)
	resolveReply, err := env.client.ResolveDocuments(env.ctx, &ResolveDocumentsRequest{
		AuthenticSource: "EHIC_DB",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "199001011234", "nationality": "SE"},
	})
	require.NoError(t, err)
	assert.Equal(t, "id-lifecycle-001", resolveReply.Identifier)
	require.Len(t, resolveReply.Documents, 1)
	assert.Equal(t, "SE-EHIC-12345", resolveReply.Documents[0].DocumentData["card_number"])

	// Step 4: Get document directly by key
	getReply, err := env.client.GetDocument(env.ctx, &GetDocumentRequest{
		AuthenticSource: "EHIC_DB", Scope: "ehic", DocumentID: "doc-lifecycle-001",
	})
	require.NoError(t, err)
	assert.Equal(t, "Försäkringskassan", getReply.Document.DocumentData["institution"])
	assert.Equal(t, validFrom, *getReply.Document.Meta.CredentialValidFrom)
	assert.Equal(t, validTo, *getReply.Document.Meta.CredentialValidTo)

	// Step 5: Update identity mapping attributes
	err = env.client.UpdateIdentityMapping(env.ctx, &UpdateIdentityMappingRequest{
		AuthenticSource: "EHIC_DB",
		Identifier:      "id-lifecycle-001",
		Attributes:      map[string]string{"ssn": "199001011234", "nationality": "SE", "email": "erik@example.com"},
	})
	require.NoError(t, err)

	// Step 6: Verify resolution still works with new attributes
	resolveReply2, err := env.client.ResolveDocuments(env.ctx, &ResolveDocumentsRequest{
		AuthenticSource: "EHIC_DB",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "199001011234", "nationality": "SE", "email": "erik@example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "id-lifecycle-001", resolveReply2.Identifier)

	// Step 7-8: Delete document and verify it's gone
	err = env.client.DeleteDocument(env.ctx, &DeleteDocumentRequest{
		AuthenticSource: "EHIC_DB", Scope: "ehic", DocumentID: "doc-lifecycle-001",
	})
	require.NoError(t, err)
	_, err = env.client.GetDocument(env.ctx, &GetDocumentRequest{
		AuthenticSource: "EHIC_DB", Scope: "ehic", DocumentID: "doc-lifecycle-001",
	})
	assert.Error(t, err)

	// Step 9-10: Delete mapping and verify it's gone
	err = env.client.DeleteIdentityMapping(env.ctx, &DeleteIdentityMappingRequest{
		AuthenticSource: "EHIC_DB", Identifier: "id-lifecycle-001",
	})
	require.NoError(t, err)
	_, err = env.client.ResolveDocuments(env.ctx, &ResolveDocumentsRequest{
		AuthenticSource: "EHIC_DB",
		Scope:           "ehic",
		Attributes:      map[string]string{"ssn": "199001011234", "nationality": "SE", "email": "erik@example.com"},
	})
	assert.Error(t, err)
}

// TestMultipleDocumentsPerIdentity verifies that one identity can have multiple documents.
func TestMultipleDocumentsPerIdentity(t *testing.T) {
	env := setupTestEnv()
	env.createMapping(t, "AS1", "multi-doc-person", map[string]string{"ssn": "010101-0101"})

	for _, scope := range []string{"ehic", "pda1", "diploma"} {
		env.uploadDoc(t, "AS1", scope, "doc-"+scope, []string{"multi-doc-person"}, map[string]any{"scope": scope})
	}

	// List all documents
	reply, err := env.client.ListDocuments(env.ctx, &ListDocumentsRequest{
		AuthenticSource: "AS1", Identifier: "multi-doc-person",
	})
	require.NoError(t, err)
	assert.Len(t, reply.Documents, 3)

	// Filter by scope
	reply, err = env.client.ListDocuments(env.ctx, &ListDocumentsRequest{
		AuthenticSource: "AS1", Identifier: "multi-doc-person", Scope: "pda1",
	})
	require.NoError(t, err)
	assert.Len(t, reply.Documents, 1)
	assert.Equal(t, "pda1", reply.Documents[0].Meta.Scope)
}

// TestMultipleIdentitiesPerDocument verifies that one document can be linked to multiple identifiers.
func TestMultipleIdentitiesPerDocument(t *testing.T) {
	env := setupTestEnv()
	env.createMapping(t, "AS1", "person-A", map[string]string{"ssn": "111111-1111"})
	env.createMapping(t, "AS1", "person-B", map[string]string{"email": "b@example.com"})

	env.uploadDoc(t, "AS1", "shared", "shared-doc", []string{"person-A", "person-B"}, map[string]any{"shared": true})

	for _, identifier := range []string{"person-A", "person-B"} {
		reply, err := env.client.ListDocuments(env.ctx, &ListDocumentsRequest{
			AuthenticSource: "AS1", Identifier: identifier, Scope: "shared",
		})
		require.NoError(t, err, "identifier: %s", identifier)
		assert.Len(t, reply.Documents, 1, "identifier: %s", identifier)
		assert.Equal(t, "shared-doc", reply.Documents[0].Meta.DocumentID)
	}
}

// TestAuthenticSourceIsolation ensures different authentic sources don't leak data.
func TestAuthenticSourceIsolation(t *testing.T) {
	env := setupTestEnv()
	env.createMapping(t, "SOURCE_A", "person-001", map[string]string{"ssn": "010101-0101"})
	env.createMapping(t, "SOURCE_B", "person-001", map[string]string{"ssn": "020202-0202"})
	env.uploadDoc(t, "SOURCE_A", "ehic", "doc-a", []string{"person-001"}, map[string]any{"source": "A"})
	env.uploadDoc(t, "SOURCE_B", "ehic", "doc-b", []string{"person-001"}, map[string]any{"source": "B"})

	// Resolve from SOURCE_A should only see SOURCE_A's document
	reply, err := env.client.ResolveDocuments(env.ctx, &ResolveDocumentsRequest{
		AuthenticSource: "SOURCE_A", Scope: "ehic",
		Attributes: map[string]string{"ssn": "010101-0101"},
	})
	require.NoError(t, err)
	require.Len(t, reply.Documents, 1)
	assert.Equal(t, "A", reply.Documents[0].DocumentData["source"])

	// Cross-source resolution should fail
	_, err = env.client.ResolveDocuments(env.ctx, &ResolveDocumentsRequest{
		AuthenticSource: "SOURCE_A", Scope: "ehic",
		Attributes: map[string]string{"ssn": "020202-0202"},
	})
	assert.Error(t, err)
}

// TestCredentialIssuanceFlow simulates the credential issuance integration path.
func TestCredentialIssuanceFlow(t *testing.T) {
	env := setupTestEnv()
	env.createMapping(t, "SUNET", "credential-subject-001",
		map[string]string{"family_name": "Johansson", "given_name": "Erik", "birth_date": "1990-01-01"})
	env.uploadDoc(t, "SUNET", "ehic", "cred-doc-001", []string{"credential-subject-001"}, map[string]any{
		"card_number": "SE-EHIC-001", "institution_id": "SE:FK",
		"institution_name": "Försäkringskassan", "valid_from": "2024-01-01", "valid_to": "2025-01-01",
	})

	// Convert v1 Identity to v2 attributes (simulating the issuance path)
	attrs := IdentityToAttributes(&model.Identity{
		FamilyName: "Johansson", GivenName: "Erik", BirthDate: "1990-01-01",
	})

	doc, err := env.client.GetDocumentForCredential(env.ctx, "SUNET", "ehic", attrs)
	require.NoError(t, err)
	assert.Equal(t, "cred-doc-001", doc.Meta.DocumentID)
	assert.Equal(t, "SE-EHIC-001", doc.DocumentData["card_number"])
}

// TestEmptyResults verifies correct behavior when no data exists.
func TestEmptyResults(t *testing.T) {
	env := setupTestEnv()

	t.Run("list documents for non-existent identifier", func(t *testing.T) {
		reply, err := env.client.ListDocuments(env.ctx, &ListDocumentsRequest{
			AuthenticSource: "SUNET", Identifier: "non-existent",
		})
		require.NoError(t, err)
		assert.Len(t, reply.Documents, 0)
	})

	t.Run("resolve with no mappings", func(t *testing.T) {
		_, err := env.client.ResolveDocuments(env.ctx, &ResolveDocumentsRequest{
			AuthenticSource: "SUNET", Scope: "ehic", Attributes: map[string]string{"ssn": "no-match"},
		})
		assert.Error(t, err)
	})

	t.Run("get non-existent document", func(t *testing.T) {
		_, err := env.client.GetDocument(env.ctx, &GetDocumentRequest{
			AuthenticSource: "SUNET", Scope: "ehic", DocumentID: "does-not-exist",
		})
		assert.Error(t, err)
	})
}

// TestDocumentDataIntegrity ensures document_data is stored and retrieved without modification.
func TestDocumentDataIntegrity(t *testing.T) {
	env := setupTestEnv()

	complexData := map[string]any{
		"string_field": "hello",
		"int_field":    float64(42),
		"bool_field":   true,
		"null_field":   nil,
		"nested":       map[string]any{"inner_string": "world", "inner_array": []any{"a", "b", "c"}},
		"array_field":  []any{float64(1), float64(2), float64(3)},
	}

	env.uploadDoc(t, "AS1", "test", "complex-doc", []string{"id-1"}, complexData)

	reply, err := env.client.GetDocument(env.ctx, &GetDocumentRequest{
		AuthenticSource: "AS1", Scope: "test", DocumentID: "complex-doc",
	})
	require.NoError(t, err)

	assert.Equal(t, "hello", reply.Document.DocumentData["string_field"])
	assert.Equal(t, float64(42), reply.Document.DocumentData["int_field"])
	assert.Equal(t, true, reply.Document.DocumentData["bool_field"])
	assert.Nil(t, reply.Document.DocumentData["null_field"])
	nested, ok := reply.Document.DocumentData["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "world", nested["inner_string"])
}

// TestOptionalMetadataFields verifies that optional metadata fields work correctly.
func TestOptionalMetadataFields(t *testing.T) {
	env := setupTestEnv()

	t.Run("document without validity dates", func(t *testing.T) {
		env.uploadDoc(t, "AS1", "test", "no-dates", []string{"id-1"}, map[string]any{"data": "value"})
		reply, err := env.client.GetDocument(env.ctx, &GetDocumentRequest{
			AuthenticSource: "AS1", Scope: "test", DocumentID: "no-dates",
		})
		require.NoError(t, err)
		assert.Nil(t, reply.Document.Meta.CredentialValidFrom)
		assert.Nil(t, reply.Document.Meta.CredentialValidTo)
		assert.Nil(t, reply.Document.Meta.Revocation)
	})

	t.Run("document with revocation info", func(t *testing.T) {
		_, err := env.client.UploadDocument(env.ctx, &UploadDocumentRequest{
			Meta: &model.V2MetaData{
				AuthenticSource: "AS1", Scope: "test", DocumentID: "revoked-doc",
				Revocation: &model.Revocation{Revoked: true},
			},
			Identities:   []string{"id-1"},
			DocumentData: map[string]any{"data": "revoked"},
		})
		require.NoError(t, err)

		reply, err := env.client.GetDocument(env.ctx, &GetDocumentRequest{
			AuthenticSource: "AS1", Scope: "test", DocumentID: "revoked-doc",
		})
		require.NoError(t, err)
		require.NotNil(t, reply.Document.Meta.Revocation)
		assert.True(t, reply.Document.Meta.Revocation.Revoked)
	})
}
