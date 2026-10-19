package apiv1

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedSecretB64 is 32 bytes, base64url as the configuration takes it.
var seedSecretB64 = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))

// commitmentClient builds an issuer configured for one seed-backed claim.
func commitmentClient(t *testing.T, format string, claim *model.CommitmentClaim, source *model.SeedSource) *Client {
	t.Helper()
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{
					"nym_auth": {
						Format:      format,
						Commitments: map[string]*model.CommitmentClaim{"ssc": claim},
					},
				},
			},
			Issuer: &model.Issuer{
				Seeds: map[string]*model.SeedSource{"primary": source},
			},
		},
	}
	return c
}

func derivedSource() *model.SeedSource {
	return &model.SeedSource{Model: model.SeedModelDerived, Secret: seedSecretB64}
}

func sscClaim() *model.CommitmentClaim {
	return &model.CommitmentClaim{Seed: "primary", Subjects: []string{"personal_administrative_number"}}
}

// scopeFormat is the format a scope is configured with, which is what a
// correctly routed handler signs it as. Tests that exercise the MISMATCH
// pass a format explicitly instead.
func scopeFormat(c *Client, scope string) string {
	meta := c.cfg.GetCredentialMetadata(scope)
	if meta == nil {
		return ""
	}
	return meta.Format
}

func inject(t *testing.T, c *Client, doc map[string]any) map[string]any {
	t.Helper()
	in, err := json.Marshal(doc)
	require.NoError(t, err)
	out, err := c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), in, model.CredentialSchemas{})
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	return got
}

// One subject, one commitment - the property everything else rests on.
// Issuing again, with different other claims, in the other format, must
// not move it, or no pseudonym built on it is reproducible.
func TestCommitmentIsStablePerSubject(t *testing.T) {
	mdocClient := commitmentClient(t, openid4vp.FormatMsoMdoc, sscClaim(), derivedSource())
	require.NoError(t, mdocClient.initSeedSources())

	first := inject(t, mdocClient, map[string]any{
		"personal_administrative_number": "198001011234",
		"birth_date":                     "1980-01-01",
	})["ssc"]
	require.NotEmpty(t, first)

	second := inject(t, mdocClient, map[string]any{
		"personal_administrative_number": "198001011234",
		"birth_date":                     "1990-02-02",
		"given_name":                     "someone else entirely",
	})["ssc"]
	assert.Equal(t, first, second, "the commitment must depend on the subject and nothing else")

	other := inject(t, mdocClient, map[string]any{
		"personal_administrative_number": "198001011235",
		"birth_date":                     "1980-01-01",
	})["ssc"]
	assert.NotEqual(t, first, other, "two subjects must not share a commitment")
}

// A subject's commitment is the same in every format. An mdoc nym_auth
// and an SD-JWT nym_auth issued to one person have to lead back to one
// person - so only the ENCODING may differ between them.
func TestCommitmentIsTheSameAcrossFormats(t *testing.T) {
	mdocClient := commitmentClient(t, openid4vp.FormatMsoMdoc, sscClaim(), derivedSource())
	require.NoError(t, mdocClient.initSeedSources())
	sdjwtClient := commitmentClient(t, openid4vp.FormatSDJWTVC, sscClaim(), derivedSource())
	require.NoError(t, sdjwtClient.initSeedSources())

	doc := map[string]any{"personal_administrative_number": "198001011234"}

	fromMdoc, ok := inject(t, mdocClient, doc)["ssc"].(string)
	require.True(t, ok)
	fromSDJWT, ok := inject(t, sdjwtClient, doc)["ssc"].(string)
	require.True(t, ok)

	// The carriers differ: an mso_mdoc bstr element arrives as JSON and is
	// decoded as standard base64, so hex there would be signed as the
	// ASCII of the hex rather than the 32 bytes. Everything else carries
	// the claim value itself, where the nym_auth circuits read hex.
	mdocBytes, err := base64.StdEncoding.DecodeString(fromMdoc)
	require.NoError(t, err, "an mso_mdoc commitment must be base64, which is what the bstr carrier decodes")
	sdjwtBytes, err := hex.DecodeString(fromSDJWT)
	require.NoError(t, err, "an SD-JWT commitment must be hex")
	assert.Equal(t, strings.ToLower(fromSDJWT), fromSDJWT, "hex must be lowercase")

	assert.Equal(t, mdocBytes, sdjwtBytes, "the same subject must commit to the same bytes in both formats")
	assert.Len(t, mdocBytes, 32)
}

// The commitment written is the one the published vector gives for that
// seed - the check that this issuer and a circuit agree about what a
// commitment is.
func TestCommitmentMatchesCommitOverTheDerivedSeed(t *testing.T) {
	c := commitmentClient(t, openid4vp.FormatSDJWTVC, sscClaim(), derivedSource())
	require.NoError(t, c.initSeedSources())

	written, ok := inject(t, c, map[string]any{"personal_administrative_number": "198001011234"})["ssc"].(string)
	require.True(t, ok)

	source := c.seedSources["primary"]
	seedValue, err := source.Seed(t.Context(), []string{"198001011234"}, "")
	require.NoError(t, err)
	expected, err := seed.Commit("", seedValue) // "" is the registered default
	require.NoError(t, err)

	assert.Equal(t, hex.EncodeToString(expected), written)
}

// An issuer-held commitment is the issuer's to compute. A value arriving
// in the document data was produced by something that does not hold the
// seed, so signing it yields a credential that looks remappable and is
// not. Refused, not overwritten: a data source supplying one is a
// misconfiguration somebody needs to hear about.
func TestUpstreamCommitmentIsRefused(t *testing.T) {
	c := commitmentClient(t, openid4vp.FormatMsoMdoc, sscClaim(), derivedSource())
	require.NoError(t, c.initSeedSources())

	in, err := json.Marshal(map[string]any{
		"personal_administrative_number": "198001011234",
		"ssc":                            base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))),
	})
	require.NoError(t, err)

	_, err = c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), in, model.CredentialSchemas{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already carries a value")
}

// No subject identifier, no issuance. Deriving over "" would hand every
// subject whose identity did not resolve the same seed, and so the same
// pseudonym - the exact failure the identifier exists to prevent,
// arriving silently.
func TestMissingSubjectRefusesIssuance(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  map[string]any
		want string
	}{
		{name: "absent", doc: map[string]any{"birth_date": "1980-01-01"}, want: "not present"},
		{name: "empty", doc: map[string]any{"personal_administrative_number": ""}, want: "is empty"},
		{name: "whitespace", doc: map[string]any{"personal_administrative_number": "   "}, want: "is empty"},
		{name: "null", doc: map[string]any{"personal_administrative_number": nil}, want: "not present"},
		{name: "not a string", doc: map[string]any{"personal_administrative_number": 198001011234}, want: "not a string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := commitmentClient(t, openid4vp.FormatMsoMdoc, sscClaim(), derivedSource())
			require.NoError(t, c.initSeedSources())

			in, err := json.Marshal(tc.doc)
			require.NoError(t, err)
			_, err = c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), in, model.CredentialSchemas{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// A scope with no commitments is untouched, including the JSON round
// trip, so nothing changes for a deployment that does not use this.
func TestScopeWithoutCommitmentsIsUntouched(t *testing.T) {
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"pid": {Format: openid4vp.FormatSDJWTVC},
		}}},
	}
	in := []byte(`{"given_name":"Anna","birth_date":"1980-01-01"}`)
	out, err := c.injectCommitments(t.Context(), "pid", scopeFormat(c, "pid"), in, model.CredentialSchemas{})
	require.NoError(t, err)
	assert.Equal(t, in, out, "the bytes must be the same bytes, not re-encoded")

	unknown, err := c.injectCommitments(t.Context(), "no-such-scope", scopeFormat(c, "no-such-scope"), in, model.CredentialSchemas{})
	require.NoError(t, err)
	assert.Equal(t, in, unknown)
}

// In a nested document a literal dotted key must NOT shadow the nested
// path. The two can carry different values, so resolving the literal one
// first would derive the seed from the wrong subject - and report nothing,
// because both lookups succeed.
func TestLiteralDottedKeyDoesNotShadowTheNestedPath(t *testing.T) {
	claim := &model.CommitmentClaim{Seed: "primary", Subjects: []string{"identity.national_number"}}
	c := commitmentClient(t, openid4vp.FormatSDJWTVC, claim, derivedSource())
	require.NoError(t, c.initSeedSources())

	// Both spellings present, carrying different people.
	got := inject(t, c, map[string]any{
		"identity.national_number": "198001011235",
		"identity":                 map[string]any{"national_number": "198001011234"},
	})

	source := c.seedSources["primary"]
	nested, err := source.Seed(t.Context(), []string{"198001011234"}, "")
	require.NoError(t, err)
	want, err := seed.Commit("", nested)
	require.NoError(t, err)

	assert.Equal(t, hex.EncodeToString(want), got["ssc"],
		"a nested format must read the nested path, not a literal key that happens to spell it")
}

// A scope signed through the wrong handler must refuse.
//
// Everything about a commitment target is decided from the CONFIGURED
// format - flat or nested document data, which schema the claim path is
// checked against, whether the VCTM disclosure rules apply at all -
// while the signing handler is chosen by the caller. A MakeSDJWT request
// naming an mso_mdoc scope therefore resolved mdoc targets and skipped
// the VCTM check that requires the commitment to be disclosable, so a
// stable per-subject identifier would be signed into the clear SD-JWT
// payload, where the holder cannot withhold it. That is the single
// property the feature exists to provide.
func TestAScopeSignedThroughTheWrongHandlerRefuses(t *testing.T) {
	doc, err := json.Marshal(map[string]any{"personal_administrative_number": "198001011234"})
	require.NoError(t, err)

	t.Run("an mdoc scope signed as SD-JWT", func(t *testing.T) {
		c := commitmentClient(t, openid4vp.FormatMsoMdoc, sscClaim(), derivedSource())
		require.NoError(t, c.initSeedSources())

		_, err := c.injectCommitments(t.Context(), "nym_auth", openid4vp.FormatSDJWTVC, doc, model.CredentialSchemas{})
		require.Error(t, err, "the commitment would be resolved by mdoc rules and signed into a clear SD-JWT payload")
		assert.Contains(t, err.Error(), "is being signed as")
	})

	t.Run("an SD-JWT scope signed as mdoc", func(t *testing.T) {
		c := commitmentClient(t, openid4vp.FormatSDJWTVC, sscClaim(), derivedSource())
		require.NoError(t, c.initSeedSources())

		_, err := c.injectCommitments(t.Context(), "nym_auth", openid4vp.FormatMsoMdoc, doc, model.CredentialSchemas{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is being signed as")
	})

	t.Run("the BBS/JWP path, which no commitment scope can match", func(t *testing.T) {
		c := commitmentClient(t, openid4vp.FormatSDJWTVC, sscClaim(), derivedSource())
		require.NoError(t, c.initSeedSources())

		_, err := c.injectCommitments(t.Context(), "nym_auth", signingFormatJWP, doc, model.CredentialSchemas{})
		require.Error(t, err)
	})

	t.Run("a handler that names no format at all", func(t *testing.T) {
		c := commitmentClient(t, openid4vp.FormatSDJWTVC, sscClaim(), derivedSource())
		require.NoError(t, c.initSeedSources())

		_, err := c.injectCommitments(t.Context(), "nym_auth", "", doc, model.CredentialSchemas{})
		require.Error(t, err, "a check that passes because nobody said is not a check")
	})

	// The legacy SD-JWT spellings are the SAME signing path, so they must
	// NOT be refused - every place that decides what a format MEANS has
	// to agree with every other.
	for _, configured := range []string{openid4vp.FormatSDJWTVC, "vc+sd-jwt", ""} {
		t.Run("configured as "+fmt.Sprintf("%q", configured)+", signed as dc+sd-jwt", func(t *testing.T) {
			c := commitmentClient(t, configured, sscClaim(), derivedSource())
			require.NoError(t, c.initSeedSources())

			_, err := c.injectCommitments(t.Context(), "nym_auth", openid4vp.FormatSDJWTVC, doc, model.CredentialSchemas{})
			require.NoError(t, err, "these are three spellings of one signing path")
		})
	}
}

// Several configured identifiers are derived over IN ORDER.
//
// One identifier is frequently not an identifier: a personnummer is
// unique within its country, a document number within its scheme. A
// deployment issuing across populations configures the discriminator
// too, and the seed must then be a function of both, in the configured
// order - not of the first one, and not of whichever the map iteration
// happened to hand over.
func TestOrderedSubjectIdentifiersAreDerivedOverInOrder(t *testing.T) {
	claim := &model.CommitmentClaim{
		Seed:     "primary",
		Subjects: []string{"issuing_country", "personal_administrative_number"},
	}
	c := commitmentClient(t, openid4vp.FormatSDJWTVC, claim, derivedSource())
	require.NoError(t, c.initSeedSources())

	doc := map[string]any{
		"issuing_country":                "SE",
		"personal_administrative_number": "198001011234",
	}
	got := inject(t, c, doc)

	source := c.seedSources["primary"]
	both, err := source.Seed(t.Context(), []string{"SE", "198001011234"}, "")
	require.NoError(t, err)
	want, err := seed.Commit("", both)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(want), got["ssc"],
		"the commitment must be over both configured identifiers, in the configured order")

	// Not the first identifier alone, which is what dropping the rest of
	// the list would silently produce.
	first, err := source.Seed(t.Context(), []string{"SE"}, "")
	require.NoError(t, err)
	alone, err := seed.Commit("", first)
	require.NoError(t, err)
	assert.NotEqual(t, hex.EncodeToString(alone), got["ssc"])

	// And order is part of the derivation: the same two identifiers
	// configured the other way round are a different subject.
	reversed := &model.CommitmentClaim{
		Seed:     "primary",
		Subjects: []string{"personal_administrative_number", "issuing_country"},
	}
	rc := commitmentClient(t, openid4vp.FormatSDJWTVC, reversed, derivedSource())
	require.NoError(t, rc.initSeedSources())
	assert.NotEqual(t, got["ssc"], inject(t, rc, doc)["ssc"],
		"reordering the configured list must repseudonymise, not be a no-op")
}

// A configured identifier that is not in the document refuses the
// issuance; it is never dropped from the list.
//
// Dropping it is the repair that looks harmless and is not: with
// ["issuing_country","pan"] and no country present, deriving over ["pan"]
// alone produces exactly the seed a single-identifier deployment issues
// for that same personnummer - so a subject missing one identifier would
// be handed another subject's pseudonym, with nothing reported.
func TestAnUnresolvedSubjectIdentifierRefusesRatherThanShorteningTheList(t *testing.T) {
	claim := &model.CommitmentClaim{
		Seed:     "primary",
		Subjects: []string{"issuing_country", "personal_administrative_number"},
	}
	c := commitmentClient(t, openid4vp.FormatSDJWTVC, claim, derivedSource())
	require.NoError(t, c.initSeedSources())

	for _, doc := range []map[string]any{
		{"personal_administrative_number": "198001011234"},
		{"issuing_country": "", "personal_administrative_number": "198001011234"},
		{"issuing_country": "SE"},
	} {
		in, err := json.Marshal(doc)
		require.NoError(t, err)
		_, err = c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), in, model.CredentialSchemas{})
		require.Errorf(t, err, "%v must refuse rather than derive over what resolved", doc)
		assert.Contains(t, err.Error(), "subject ")
	}
}

// And the commitment itself is written nested, where the format has
// nesting - otherwise the signer looks for a claim that is not there.
func TestNestedFormatWritesTheCommitmentNested(t *testing.T) {
	claim := &model.CommitmentClaim{Seed: "primary", Subjects: []string{"national_number"}}
	c := commitmentClient(t, openid4vp.FormatSDJWTVC, claim, derivedSource())
	c.cfg.Common.CredentialMetadata["nym_auth"].Commitments = map[string]*model.CommitmentClaim{
		"nym.ssc": claim,
	}
	require.NoError(t, c.initSeedSources())

	got := inject(t, c, map[string]any{"national_number": "198001011234"})
	nested, ok := got["nym"].(map[string]any)
	require.True(t, ok, "a dotted claim path in a nested format must create the object")
	assert.NotEmpty(t, nested["ssc"])
	assert.NotContains(t, got, "nym.ssc", "and must not also write it flat")
}

// An intermediate segment that already holds a scalar is a path
// conflict, and must refuse.
//
// Creating the map anyway - which is what a plain type assertion does -
// DELETES that claim on the way to signing, and the credential is issued
// missing an attribute nobody asked to remove. Silently, because the
// injection succeeded.
func TestPathConflictRefusesRatherThanDeletingTheClaim(t *testing.T) {
	claim := &model.CommitmentClaim{Seed: "primary", Subjects: []string{"national_number"}}
	c := commitmentClient(t, openid4vp.FormatSDJWTVC, claim, derivedSource())
	c.cfg.Common.CredentialMetadata["nym_auth"].Commitments = map[string]*model.CommitmentClaim{
		"identity.ssc": claim,
	}
	require.NoError(t, c.initSeedSources())

	in, err := json.Marshal(map[string]any{
		"national_number": "198001011234",
		"identity":        "a claim that is already there",
	})
	require.NoError(t, err)

	_, err = c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), in, model.CredentialSchemas{})
	require.Error(t, err, "a path conflict must refuse the issuance")
	assert.Contains(t, err.Error(), "path conflict")
}

// An mdoc signer emits the elements its schema declares and silently
// ignores anything else in the document. A commitment path the schema
// does not declare therefore injects cleanly and issues a credential with
// no commitment in it, reporting nothing.
func TestMdocSchemaMustDeclareTheCommitmentTarget(t *testing.T) {
	schema := &mdoc.MDDLSchema{
		DocType: "eu.europa.ec.eudi.nym_auth.1",
		Claims: map[string]mdoc.NamespaceClaims{
			"eu.europa.ec.eudi.nym_auth.1": {
				"birth_date": {Mandatory: true, ValueType: "full-date"},
				"ssc":        {Mandatory: true, ValueType: "bstr"},
			},
		},
	}

	doc, err := json.Marshal(map[string]any{"personal_administrative_number": "198001011234"})
	require.NoError(t, err)

	t.Run("declared, bare", func(t *testing.T) {
		c := commitmentClient(t, openid4vp.FormatMsoMdoc, sscClaim(), derivedSource())
		require.NoError(t, c.initSeedSources())
		_, err := c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), doc, model.CredentialSchemas{MDoc: schema})
		assert.NoError(t, err)
	})

	t.Run("declared, namespace-qualified, written at the bare element id", func(t *testing.T) {
		claim := sscClaim()
		c := commitmentClient(t, openid4vp.FormatMsoMdoc, claim, derivedSource())
		c.cfg.Common.CredentialMetadata["nym_auth"].Commitments = map[string]*model.CommitmentClaim{
			"eu.europa.ec.eudi.nym_auth.1.ssc": claim,
		}
		require.NoError(t, c.initSeedSources())

		out, err := c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), doc, model.CredentialSchemas{MDoc: schema})
		require.NoError(t, err, "the namespace-qualified spelling is how the claim is named everywhere else")

		var got map[string]any
		require.NoError(t, json.Unmarshal(out, &got))
		assert.NotEmpty(t, got["ssc"],
			"an mdoc document is keyed by bare element identifier; writing the qualified path verbatim would be dropped by the signer")
		assert.NotContains(t, got, "eu.europa.ec.eudi.nym_auth.1.ssc")
	})

	// The dangerous half of the same bug: with a qualified configuration,
	// an upstream BARE value is the one the signer reads, so missing it
	// means signing a commitment the issuer did not compute.
	t.Run("a qualified target still detects an upstream bare value", func(t *testing.T) {
		claim := sscClaim()
		c := commitmentClient(t, openid4vp.FormatMsoMdoc, claim, derivedSource())
		c.cfg.Common.CredentialMetadata["nym_auth"].Commitments = map[string]*model.CommitmentClaim{
			"eu.europa.ec.eudi.nym_auth.1.ssc": claim,
		}
		require.NoError(t, c.initSeedSources())

		withUpstream, err := json.Marshal(map[string]any{
			"personal_administrative_number": "198001011234",
			"ssc":                            base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))),
		})
		require.NoError(t, err)

		_, err = c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), withUpstream, model.CredentialSchemas{MDoc: schema})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already carries a value")
	})

	// A bstr element is decoded as standard base64, and a 64-character hex
	// commitment is itself valid base64 - so hex does not fail here, it
	// decodes to 48 bytes of nothing and signs those.
	t.Run("hex against a bstr target", func(t *testing.T) {
		claim := sscClaim()
		claim.Encoding = "hex"
		c := commitmentClient(t, openid4vp.FormatMsoMdoc, claim, derivedSource())
		require.NoError(t, c.initSeedSources())

		_, err := c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), doc, model.CredentialSchemas{MDoc: schema})
		require.Error(t, err, "a 64-character hex string decodes as base64 to 48 bytes, and nothing downstream could tell")
		assert.Contains(t, err.Error(), "bstr")
	})

	t.Run("not declared", func(t *testing.T) {
		claim := sscClaim()
		c := commitmentClient(t, openid4vp.FormatMsoMdoc, claim, derivedSource())
		c.cfg.Common.CredentialMetadata["nym_auth"].Commitments = map[string]*model.CommitmentClaim{
			"psc": claim,
		}
		require.NoError(t, c.initSeedSources())
		_, err := c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), doc, model.CredentialSchemas{MDoc: schema})
		require.Error(t, err, "the signer would drop it and issue a credential without the commitment")
		assert.Contains(t, err.Error(), "declares no such element")
	})
}

// Subject identifiers are resolved from the document AS RECEIVED, before
// anything is written to it.
//
// Resolving inside the write loop lets one commitment derive from
// another's freshly injected value. Sorting the claim paths makes that
// deterministic but not correct: with "a_ssc" written before "z_other",
// z_other's subject path "a_ssc" finds the commitment just written and
// derives a seed from it - silently, and from a value that identifies
// nobody. Subject is documented as coming from the received document
// data, so it reads the received document data and this refuses.
func TestSubjectsResolveAgainstTheReceivedDocument(t *testing.T) {
	c := commitmentClient(t, openid4vp.FormatSDJWTVC, sscClaim(), derivedSource())
	c.cfg.Common.CredentialMetadata["nym_auth"].Commitments = map[string]*model.CommitmentClaim{
		"a_ssc": {Seed: "primary", Subjects: []string{"personal_administrative_number"}},
		// Sorts AFTER a_ssc, and its subject is a_ssc's target - which the
		// received document does not carry.
		"z_other": {Seed: "primary", Subjects: []string{"a_ssc"}},
	}
	require.NoError(t, c.initSeedSources())

	in, err := json.Marshal(map[string]any{"personal_administrative_number": "198001011234"})
	require.NoError(t, err)

	_, err = c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), in, model.CredentialSchemas{})
	require.Error(t, err, "a subject that is not in the received document must refuse")
	assert.Contains(t, err.Error(), "not present",
		"and must never derive from a commitment written earlier in the same pass")
}

// The same request must produce the same credential every time. Go's map
// iteration order is deliberately randomised, so a pass that reads and
// writes the same document in one loop can differ between runs.
func TestInjectionIsOrderIndependent(t *testing.T) {
	var first map[string]any
	for i := range 50 {
		c := commitmentClient(t, openid4vp.FormatSDJWTVC, sscClaim(), derivedSource())
		c.cfg.Common.CredentialMetadata["nym_auth"].Commitments = map[string]*model.CommitmentClaim{
			"ssc":   {Seed: "primary", Subjects: []string{"personal_administrative_number"}},
			"other": {Seed: "primary", Subjects: []string{"given_name"}, Context: "other"},
			"third": {Seed: "primary", Subjects: []string{"family_name"}, Context: "third"},
		}
		require.NoError(t, c.initSeedSources())

		got := inject(t, c, map[string]any{
			"personal_administrative_number": "198001011234",
			"given_name":                     "Anna",
			"family_name":                    "Andersson",
		})
		if i == 0 {
			first = got
			continue
		}
		assert.Equal(t, first, got, "two passes over the same request produced different documents")
	}
}

// Startup refusals. Each of these is a configuration that would otherwise
// issue a credential with no commitment, the wrong one, or a commitment
// nobody can reproduce - all of which are found long after the fact.
func TestStartupRefusesAConfigurationItCannotHonour(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(c *Client)
		want   string
	}{
		{
			name:   "a stored seed source, which needs a store this issuer has not got",
			mutate: func(c *Client) { c.cfg.Issuer.Seeds["primary"].Model = model.SeedModelStored },
			want:   "not implemented yet",
		},
		{
			name:   "an unknown seed model",
			mutate: func(c *Client) { c.cfg.Issuer.Seeds["primary"].Model = "magic" },
			want:   "unknown model",
		},
		{
			name: "a holder-supplied commitment, which needs a record this issuer cannot keep",
			mutate: func(c *Client) {
				c.cfg.Common.CredentialMetadata["nym_auth"].Commitments["ssc"] = &model.CommitmentClaim{Source: "holder"}
			},
			want: "not implemented yet",
		},
		{
			name: "a claim naming a seed source that does not exist",
			mutate: func(c *Client) {
				c.cfg.Common.CredentialMetadata["nym_auth"].Commitments["ssc"].Seed = "typo"
			},
			want: "not configured in issuer.seeds",
		},
		{
			name: "a claim naming no seed source at all",
			mutate: func(c *Client) {
				c.cfg.Common.CredentialMetadata["nym_auth"].Commitments["ssc"].Seed = ""
			},
			want: "no seed source named",
		},
		{
			name: "a claim with no subject paths",
			mutate: func(c *Client) {
				c.cfg.Common.CredentialMetadata["nym_auth"].Commitments["ssc"].Subjects = nil
			},
			want: "no subject paths named",
		},
		{
			name: "a claim with an empty subject path among several",
			mutate: func(c *Client) {
				c.cfg.Common.CredentialMetadata["nym_auth"].Commitments["ssc"].Subjects = []string{"issuing_country", "  "}
			},
			want: "subject path 2 of 2 is empty",
		},
		{
			name: "an unregistered commitment function",
			mutate: func(c *Client) {
				c.cfg.Common.CredentialMetadata["nym_auth"].Commitments["ssc"].Commit = "sha3-256"
			},
			want: "unknown commitment function",
		},
		{
			name: "an unknown encoding",
			mutate: func(c *Client) {
				c.cfg.Common.CredentialMetadata["nym_auth"].Commitments["ssc"].Encoding = "base58"
			},
			want: "unknown encoding",
		},
		{
			name:   "no derivation secret",
			mutate: func(c *Client) { c.cfg.Issuer.Seeds["primary"].Secret = "" },
			want:   "set secret_path, or issuer.seeds.primary.secret in the secrets file",
		},
		{
			name: "two sources of truth for the derivation secret",
			mutate: func(c *Client) {
				c.cfg.Issuer.Seeds["primary"].SecretPath = "/etc/vc/seed.key"
			},
			want: "not both",
		},
		{
			name: "a derivation secret below the minimum",
			mutate: func(c *Client) {
				c.cfg.Issuer.Seeds["primary"].Secret = base64.RawURLEncoding.EncodeToString([]byte("too short"))
			},
			want: "shorter than",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := commitmentClient(t, openid4vp.FormatMsoMdoc, sscClaim(), derivedSource())
			tc.mutate(c)
			err := c.initSeedSources()
			require.Error(t, err, "this configuration must stop the issuer starting")
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// The secret is the one thing here that must never reach a log, and a
// startup error is the most likely way it would: the code that reports a
// bad secret is holding it.
func TestStartupErrorsDoNotCarryTheSecret(t *testing.T) {
	raw := strings.Repeat("s", 32)
	c := commitmentClient(t, openid4vp.FormatMsoMdoc, sscClaim(), derivedSource())
	c.cfg.Issuer.Seeds["primary"].SecretPath = "/etc/vc/seed.key" // both set, so it fails

	err := c.initSeedSources()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), raw)
	assert.NotContains(t, err.Error(), seedSecretB64)
}

// The subject identifier names the person. A derivation failure reports
// the claim and the scope, never the identifier.
func TestInjectionErrorsDoNotCarryTheSubject(t *testing.T) {
	c := commitmentClient(t, openid4vp.FormatMsoMdoc, sscClaim(), derivedSource())
	require.NoError(t, c.initSeedSources())

	// Broken AFTER startup, since startup is what normally refuses this -
	// the point here is what the injection path says when it is reached.
	c.cfg.Common.CredentialMetadata["nym_auth"].Commitments["ssc"].Commit = "sha3-256"

	in, err := json.Marshal(map[string]any{"personal_administrative_number": "198001011234"})
	require.NoError(t, err)
	_, err = c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), in, model.CredentialSchemas{})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "198001011234",
		"an error about a commitment must not name the person it was for")
}

// A dotted subject path reaches into a nested document, and a flat
// element identifier that happens to contain dots is found where it
// actually is rather than descended into.
func TestPathResolution(t *testing.T) {
	t.Run("nested", func(t *testing.T) {
		claim := &model.CommitmentClaim{Seed: "primary", Subjects: []string{"identity.national_number"}}
		c := commitmentClient(t, openid4vp.FormatSDJWTVC, claim, derivedSource())
		require.NoError(t, c.initSeedSources())

		got := inject(t, c, map[string]any{
			"identity": map[string]any{"national_number": "198001011234"},
		})
		assert.NotEmpty(t, got["ssc"])
	})

	t.Run("a flat key containing dots", func(t *testing.T) {
		claim := &model.CommitmentClaim{Seed: "primary", Subjects: []string{"eu.europa.ec.eudi.pid.1.personal_administrative_number"}}
		c := commitmentClient(t, openid4vp.FormatMsoMdoc, claim, derivedSource())
		c.cfg.Common.CredentialMetadata["nym_auth"].Commitments = map[string]*model.CommitmentClaim{
			"eu.europa.ec.eudi.nym_auth.1.ssc": claim,
		}
		require.NoError(t, c.initSeedSources())

		got := inject(t, c, map[string]any{
			"eu.europa.ec.eudi.pid.1.personal_administrative_number": "198001011234",
		})
		assert.NotEmpty(t, got["eu.europa.ec.eudi.nym_auth.1.ssc"],
			"a dotted element identifier must be written flat, as mdoc document data is")
	})
}

// Injecting a commitment must not rewrite claims it never touched.
//
// Decoding into map[string]any turns every JSON number into a float64,
// and marshalling that back changes any integer past 2^53. MakeJWP
// forwarded the document untouched before this feature existed, so
// without UseNumber the injection is a silent data change for every
// number in every document it passes through.
func TestInjectionPreservesEveryOtherClaimExactly(t *testing.T) {
	c := commitmentClient(t, openid4vp.FormatSDJWTVC, sscClaim(), derivedSource())
	require.NoError(t, c.initSeedSources())

	in := []byte(`{"personal_administrative_number":"198001011234",` +
		`"big":9007199254740993,` +
		`"precise":0.1234567890123456789,` +
		`"huge":123456789012345678901234567890,` +
		`"negative":-9007199254740993,` +
		`"nested":{"also_big":9007199254740993}}`)

	out, err := c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), in, model.CredentialSchemas{})
	require.NoError(t, err)

	var got map[string]any
	decoder := json.NewDecoder(bytes.NewReader(out))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&got))

	assert.Equal(t, json.Number("9007199254740993"), got["big"])
	assert.Equal(t, json.Number("0.1234567890123456789"), got["precise"])
	assert.Equal(t, json.Number("123456789012345678901234567890"), got["huge"])
	assert.Equal(t, json.Number("-9007199254740993"), got["negative"])
	nested, ok := got["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, json.Number("9007199254740993"), nested["also_big"])

	assert.NotEmpty(t, got["ssc"], "and the commitment is still written")
}

// A Decoder stops at the end of the first JSON value, so trailing bytes
// decode happily and re-marshal as valid JSON. That is strictly weaker
// than the Unmarshal this replaced: MakeVC20 had full-input validation
// before, and the JWP validator still assumes it.
func TestTrailingBytesAfterTheDocumentAreRefused(t *testing.T) {
	c := commitmentClient(t, openid4vp.FormatSDJWTVC, sscClaim(), derivedSource())
	require.NoError(t, c.initSeedSources())

	for _, tc := range []struct {
		name string
		in   string
	}{
		{name: "a bare word", in: `{"personal_administrative_number":"198001011234"} trailing`},
		{name: "a second object", in: `{"personal_administrative_number":"198001011234"}{"more":1}`},
		{name: "a stray brace", in: `{"personal_administrative_number":"198001011234"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), []byte(tc.in), model.CredentialSchemas{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "trailing")
		})
	}

	// The case Buffered() cannot see: a Decoder only exposes what it
	// happened to prefetch, so with enough whitespace between the object
	// and the garbage the buffer holds nothing but whitespace and the
	// check passes on an input written to fail it.
	t.Run("beyond the decoder's prefetch", func(t *testing.T) {
		far := `{"personal_administrative_number":"198001011234"}` +
			strings.Repeat(" ", 64*1024) + "trailing"
		_, err := c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"), []byte(far), model.CredentialSchemas{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trailing")
	})

	// Trailing WHITESPACE is not trailing garbage.
	_, err := c.injectCommitments(t.Context(), "nym_auth", scopeFormat(c, "nym_auth"),
		[]byte("{\"personal_administrative_number\":\"198001011234\"}\n\t "), model.CredentialSchemas{})
	assert.NoError(t, err)
}
