package apiv1

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
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
	const birthDate = "eu.europa.ec.eudi.pid.1.birth_date"
	verified, err := verifiedClaims(openid4vp.FormatMsoMdoc, map[string]any{
		birthDate: cbor.Tag{Number: mdoc.TagDate, Content: "1990-01-15"},
	}, map[string][]string{birthDate: nil})
	require.NoError(t, err)

	raw, err := bson.Marshal(&cache.AuthorizationContext{SessionID: "s", PresentedScope: "pid_mdoc", VerifiedClaims: verified})
	require.NoError(t, err)
	var stored cache.AuthorizationContext
	require.NoError(t, bson.Unmarshal(raw, &stored))

	c := &Client{cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		"nym_auth": {Format: openid4vp.FormatMsoMdoc, MDDL: &mdoc.MDDLSchema{Claims: map[string]mdoc.NamespaceClaims{
			"eu.europa.ec.eudi.nym_auth.1": {"birth_date": {ValueType: "full-date"}},
		}}},
	}}}}
	pScope := model.PresentationScope{From: map[string]model.PresentedCredential{"pid_mdoc": {
		Derivations: []primitives.Derivation{{Copy: &primitives.CopyArgs{Input: birthDate, Output: "birth_date"}}},
	}}}
	doc, err := c.buildPresentationDocument("nym_auth", pScope, &stored, time.Now())
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"birth_date": "1990-01-15"}, doc)
}
