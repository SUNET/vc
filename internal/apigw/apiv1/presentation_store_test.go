package apiv1

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// An mdoc PID's verified claims issue their document after the auth
// context goes through the BSON encoding of the Mongo-backed store, as
// issuance under HA reads them.
func TestVerifiedMDocClaimsIssueAfterTheMongoStore(t *testing.T) {
	birthDate := claimpath.Keys("eu.europa.ec.eudi.pid.1", "birth_date")
	verified, err := verifiedClaims(openid4vp.PresentedShape(openid4vp.FormatMsoMdoc), map[string]any{
		"eu.europa.ec.eudi.pid.1.birth_date": cbor.Tag{Number: mdoc.TagDate, Content: "1990-01-15"},
	}, model.RequiredClaims{{Path: birthDate}})
	require.NoError(t, err)
	storable, err := documentObject(verified)
	require.NoError(t, err)

	raw, err := bson.Marshal(&cache.AuthorizationContext{SessionID: "s", PresentedScope: "pid_mdoc", VerifiedClaims: storable})
	require.NoError(t, err)
	var stored cache.AuthorizationContext
	require.NoError(t, bson.Unmarshal(raw, &stored))

	c := &Client{cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		"nym_auth": {Format: openid4vp.FormatMsoMdoc, MDDL: &mdoc.MDDLSchema{Claims: map[string]mdoc.NamespaceClaims{
			"eu.europa.ec.eudi.nym_auth.1": {"birth_date": {ValueType: "full-date"}},
		}}},
		"pid_mdoc": {Format: openid4vp.FormatMsoMdoc},
	}}}}
	pScope := model.PresentationScope{From: map[string]model.PresentedCredential{"pid_mdoc": {
		Derivations: []primitives.Derivation{{Copy: &primitives.CopyArgs{Input: birthDate, Output: claimpath.Keys("eu.europa.ec.eudi.nym_auth.1", "birth_date")}}},
	}}}
	doc, err := c.buildPresentationDocument("nym_auth", pScope, &stored, time.Now())
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"birth_date": "1990-01-15"}, doc)
}

// A map or array element passes only the fields its MDDL Elements declare.
func TestFilterAgainstMDDLDropsUndeclaredNestedFields(t *testing.T) {
	schema := &mdoc.MDDLSchema{Claims: map[string]mdoc.NamespaceClaims{"ns": {
		"identity": {ValueType: "map", Elements: map[string]mdoc.ClaimMetadata{
			"given_name": {ValueType: "tstr"},
			"born":       {ValueType: "full-date"},
		}},
		"privileges": {ValueType: "array", Elements: map[string]mdoc.ClaimMetadata{
			"category": {ValueType: "tstr"},
		}},
		"free_form": {ValueType: "map"},
	}}}
	doc := map[string]any{
		"identity": map[string]any{"given_name": "Alex", "born": "1990-01-15", "personal_administrative_number": "pan-1"},
		"privileges": []any{
			map[string]any{"category": "B", "secret": "x"},
			"not-a-map",
		},
		"free_form": map[string]any{"kept": true},
	}

	out, err := filterAgainstMDDL(doc, schema)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"identity":   map[string]any{"given_name": "Alex", "born": "1990-01-15"},
		"privileges": []any{map[string]any{"category": "B"}, "not-a-map"},
		"free_form":  map[string]any{"kept": true},
	}, out)

	_, err = filterAgainstMDDL(map[string]any{"identity": "flat"}, schema)
	require.Error(t, err, "a declared map holding a string is refused")
}
