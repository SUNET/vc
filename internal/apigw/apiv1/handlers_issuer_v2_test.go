package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityToV2Attributes(t *testing.T) {
	t.Run("nil identity", func(t *testing.T) {
		attrs := identityToV2Attributes(nil)
		assert.Nil(t, attrs)
	})

	t.Run("full identity", func(t *testing.T) {
		identity := &model.Identity{
			FamilyName:                   "Johansson",
			GivenName:                    "Erik",
			BirthDate:                    "1990-01-01",
			PersonalAdministrativeNumber: "199001011234",
		}
		attrs := identityToV2Attributes(identity)
		assert.Equal(t, "Johansson", attrs["family_name"])
		assert.Equal(t, "Erik", attrs["given_name"])
		assert.Equal(t, "1990-01-01", attrs["birth_date"])
		assert.Equal(t, "199001011234", attrs["personal_administrative_number"])
		assert.Len(t, attrs, 4)
	})

	t.Run("partial identity - name only", func(t *testing.T) {
		identity := &model.Identity{
			FamilyName: "Johansson",
			GivenName:  "Erik",
		}
		attrs := identityToV2Attributes(identity)
		assert.Equal(t, "Johansson", attrs["family_name"])
		assert.Equal(t, "Erik", attrs["given_name"])
		assert.Len(t, attrs, 2)
	})

	t.Run("empty identity", func(t *testing.T) {
		identity := &model.Identity{}
		attrs := identityToV2Attributes(identity)
		assert.NotNil(t, attrs)
		assert.Len(t, attrs, 0)
	})
}

func TestV2DocumentToCompleteDocument(t *testing.T) {
	t.Run("basic conversion", func(t *testing.T) {
		validFrom := int64(1700000000)
		validTo := int64(1800000000)
		v2Doc := &model.V2Document{
			Meta: &model.V2MetaData{
				AuthenticSource:     "SUNET",
				Scope:               "ehic",
				DocumentID:          "doc-001",
				CredentialValidFrom: &validFrom,
				CredentialValidTo:   &validTo,
			},
			Identities:   []string{"person-001"},
			DocumentData: map[string]any{"card_number": "SE-123"},
		}

		complete := v2DocumentToCompleteDocument(v2Doc)

		require.NotNil(t, complete)
		require.NotNil(t, complete.Meta)
		assert.Equal(t, "SUNET", complete.Meta.AuthenticSource)
		assert.Equal(t, "ehic", complete.Meta.Scope)
		assert.Equal(t, "doc-001", complete.Meta.DocumentID)
		assert.Equal(t, int64(1700000000), complete.Meta.CredentialValidFrom)
		assert.Equal(t, int64(1800000000), complete.Meta.CredentialValidTo)
		assert.Nil(t, complete.Identities) // v2 doesn't carry structured identities
		assert.Equal(t, "SE-123", complete.DocumentData["card_number"])
	})

	t.Run("without optional validity dates", func(t *testing.T) {
		v2Doc := &model.V2Document{
			Meta: &model.V2MetaData{
				AuthenticSource: "SUNET",
				Scope:           "ehic",
				DocumentID:      "doc-002",
			},
			Identities:   []string{"person-001"},
			DocumentData: map[string]any{"data": "value"},
		}

		complete := v2DocumentToCompleteDocument(v2Doc)

		assert.Equal(t, int64(0), complete.Meta.CredentialValidFrom) // zero value
		assert.Equal(t, int64(0), complete.Meta.CredentialValidTo)
		assert.Nil(t, complete.Meta.Revocation)
	})

	t.Run("with revocation", func(t *testing.T) {
		v2Doc := &model.V2Document{
			Meta: &model.V2MetaData{
				AuthenticSource: "SUNET",
				Scope:           "ehic",
				DocumentID:      "doc-003",
				Revocation: &model.Revocation{
					ID:      "rev-001",
					Revoked: true,
				},
			},
			Identities:   []string{"person-001"},
			DocumentData: map[string]any{"data": "revoked"},
		}

		complete := v2DocumentToCompleteDocument(v2Doc)

		require.NotNil(t, complete.Meta.Revocation)
		assert.Equal(t, "rev-001", complete.Meta.Revocation.ID)
		assert.True(t, complete.Meta.Revocation.Revoked)
	})

	t.Run("document_data preserved", func(t *testing.T) {
		v2Doc := &model.V2Document{
			Meta: &model.V2MetaData{
				AuthenticSource: "SUNET",
				Scope:           "ehic",
				DocumentID:      "doc-004",
			},
			Identities: []string{"person-001"},
			DocumentData: map[string]any{
				"card_number": "SE-EHIC-001",
				"nested":      map[string]any{"key": "value"},
				"list":        []any{"a", "b"},
			},
		}

		complete := v2DocumentToCompleteDocument(v2Doc)

		assert.Equal(t, "SE-EHIC-001", complete.DocumentData["card_number"])
		nested, ok := complete.DocumentData["nested"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "value", nested["key"])
	})
}
