package apiv2

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDocumentForCredential(t *testing.T) {
	env := setupTestEnv()

	// Setup: create identity mapping and document via helpers
	env.createMapping(t, "SUNET", "person-001",
		map[string]string{"family_name": "Johansson", "given_name": "Erik", "birth_date": "1990-01-01"})
	env.uploadDoc(t, "SUNET", "ehic", "doc-001", []string{"person-001"}, map[string]any{"card_number": "SE-123-456"})

	t.Run("successful resolution", func(t *testing.T) {
		doc, err := env.client.GetDocumentForCredential(env.ctx, "SUNET", "ehic",
			map[string]string{"family_name": "Johansson", "given_name": "Erik", "birth_date": "1990-01-01"})
		require.NoError(t, err)
		assert.Equal(t, "doc-001", doc.Meta.DocumentID)
		assert.Equal(t, "SE-123-456", doc.DocumentData["card_number"])
	})

	t.Run("unknown identity attributes", func(t *testing.T) {
		_, err := env.client.GetDocumentForCredential(env.ctx, "SUNET", "ehic",
			map[string]string{"family_name": "Unknown", "given_name": "Person"})
		assert.Error(t, err)
	})

	t.Run("identity resolves but no matching document for scope", func(t *testing.T) {
		doc, err := env.client.GetDocumentForCredential(env.ctx, "SUNET", "pda1",
			map[string]string{"family_name": "Johansson", "given_name": "Erik", "birth_date": "1990-01-01"})
		if err == nil {
			assert.Nil(t, doc)
		} else {
			assert.Error(t, err)
		}
	})

	t.Run("wrong authentic source", func(t *testing.T) {
		_, err := env.client.GetDocumentForCredential(env.ctx, "OTHER_SOURCE", "ehic",
			map[string]string{"family_name": "Johansson", "given_name": "Erik", "birth_date": "1990-01-01"})
		assert.Error(t, err)
	})
}

func TestGetDocumentByIdentifier(t *testing.T) {
	env := setupTestEnv()
	env.uploadDoc(t, "SUNET", "ehic", "doc-001", []string{"person-001"}, map[string]any{"card_number": "SE-123"})

	t.Run("existing document", func(t *testing.T) {
		doc, err := env.client.GetDocumentByIdentifier(env.ctx, "SUNET", "ehic", "person-001")
		require.NoError(t, err)
		assert.Equal(t, "doc-001", doc.Meta.DocumentID)
	})

	t.Run("non-existent identifier", func(t *testing.T) {
		_, err := env.client.GetDocumentByIdentifier(env.ctx, "SUNET", "ehic", "non-existent")
		assert.Error(t, err)
	})

	t.Run("non-existent scope", func(t *testing.T) {
		_, err := env.client.GetDocumentByIdentifier(env.ctx, "SUNET", "pda1", "person-001")
		assert.Error(t, err)
	})
}

func TestIdentityToAttributes(t *testing.T) {
	t.Run("nil identity", func(t *testing.T) {
		attrs := IdentityToAttributes(nil)
		assert.Nil(t, attrs)
	})

	t.Run("full identity", func(t *testing.T) {
		attrs := IdentityToAttributes(&model.Identity{
			FamilyName:                   "Johansson",
			GivenName:                    "Erik",
			BirthDate:                    "1990-01-01",
			PersonalAdministrativeNumber: "199001011234",
		})
		assert.Equal(t, "Johansson", attrs["family_name"])
		assert.Equal(t, "Erik", attrs["given_name"])
		assert.Equal(t, "1990-01-01", attrs["birth_date"])
		assert.Equal(t, "199001011234", attrs["personal_administrative_number"])
	})

	t.Run("partial identity", func(t *testing.T) {
		attrs := IdentityToAttributes(&model.Identity{
			FamilyName: "Johansson",
		})
		assert.Equal(t, "Johansson", attrs["family_name"])
		assert.Len(t, attrs, 1)
	})

	t.Run("empty identity", func(t *testing.T) {
		attrs := IdentityToAttributes(&model.Identity{})
		assert.NotNil(t, attrs)
		assert.Len(t, attrs, 0)
	})
}

func TestHasDocument(t *testing.T) {
	env := setupTestEnv()
	env.createMapping(t, "SUNET", "person-001", map[string]string{"ssn": "010101-0101"})
	env.uploadDoc(t, "SUNET", "ehic", "doc-001", []string{"person-001"}, map[string]any{"test": true})

	t.Run("document exists", func(t *testing.T) {
		result := env.client.HasDocument(env.ctx, "SUNET", "ehic", map[string]string{"ssn": "010101-0101"})
		assert.True(t, result)
	})

	t.Run("document does not exist for scope", func(t *testing.T) {
		result := env.client.HasDocument(env.ctx, "SUNET", "pda1", map[string]string{"ssn": "010101-0101"})
		assert.False(t, result)
	})

	t.Run("identity not found", func(t *testing.T) {
		result := env.client.HasDocument(env.ctx, "SUNET", "ehic", map[string]string{"ssn": "999999-9999"})
		assert.False(t, result)
	})

	t.Run("empty attributes", func(t *testing.T) {
		result := env.client.HasDocument(env.ctx, "SUNET", "ehic", map[string]string{})
		assert.False(t, result)
	})

	t.Run("nil attributes", func(t *testing.T) {
		result := env.client.HasDocument(env.ctx, "SUNET", "ehic", nil)
		assert.False(t, result)
	})
}
