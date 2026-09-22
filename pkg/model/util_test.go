package model

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoolVal(t *testing.T) {
	tests := []struct {
		name     string
		b        *bool
		fallback bool
		want     bool
	}{
		{"nil with false fallback", nil, false, false},
		{"nil with true fallback", nil, true, true},
		{"true pointer", new(true), false, true},
		{"false pointer", new(false), true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BoolVal(tt.b, tt.fallback)
			if got != tt.want {
				t.Errorf("BoolVal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractIdentityClaims(t *testing.T) {
	required := []string{"sub", "email", "name"}

	claims := map[string]any{
		"sub":   "user123",
		"email": "test@example.com",
		"age":   30, // extra non-string claim; not required here, so it should be ignored
	}

	_, err := ExtractIdentityClaims(claims, required)
	if err == nil {
		t.Fatal("expected error for missing/non-string claims")
	}

	// With all required claims present as strings
	claims["name"] = "Test User"
	delete(claims, "age")
	result, err := ExtractIdentityClaims(claims, []string{"sub", "email"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["sub"] != "user123" {
		t.Errorf("expected sub=user123, got %s", result["sub"])
	}
	if result["email"] != "test@example.com" {
		t.Errorf("expected email=test@example.com, got %s", result["email"])
	}
}

func TestExtractIdentityClaims_Empty(t *testing.T) {
	result, err := ExtractIdentityClaims(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestExtractIdentityClaims_MissingClaim(t *testing.T) {
	claims := map[string]any{
		"given_name": "John",
	}
	_, err := ExtractIdentityClaims(claims, []string{"given_name", "family_name"})
	if err == nil {
		t.Fatal("expected error for missing claim")
	}
}

func TestExtractIdentityClaims_NonStringClaim(t *testing.T) {
	claims := map[string]any{
		"given_name": "John",
		"age":        30,
	}
	_, err := ExtractIdentityClaims(claims, []string{"given_name", "age"})
	if err == nil {
		t.Fatal("expected error for non-string claim")
	}
}

func TestIdentity_GetAgeInYears(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name      string
		birthDate string
		wantAge   int
		wantErr   bool
	}{
		{"30 years ago", now.AddDate(-30, 0, 0).Format("2006-01-02"), 30, false},
		{"just born", now.Format("2006-01-02"), 0, false},
		{"invalid date", "not-a-date", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := &Identity{BirthDate: tt.birthDate}
			age, err := id.GetAgeInYears()
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && age != tt.wantAge {
				t.Errorf("age = %d, want %d", age, tt.wantAge)
			}
		})
	}
}

func TestIdentity_GetOverAge(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name      string
		birthDate string
		fn        func(*Identity) (bool, error)
		want      bool
	}{
		{"over16 yes", now.AddDate(-17, 0, 0).Format("2006-01-02"), (*Identity).GetOver16, true},
		{"over16 no", now.AddDate(-15, 0, 0).Format("2006-01-02"), (*Identity).GetOver16, false},
		{"over18 yes", now.AddDate(-19, 0, 0).Format("2006-01-02"), (*Identity).GetOver18, true},
		{"over18 no", now.AddDate(-17, 0, 0).Format("2006-01-02"), (*Identity).GetOver18, false},
		{"over21 yes", now.AddDate(-22, 0, 0).Format("2006-01-02"), (*Identity).GetOver21, true},
		{"over21 no", now.AddDate(-20, 0, 0).Format("2006-01-02"), (*Identity).GetOver21, false},
		{"over65 yes", now.AddDate(-66, 0, 0).Format("2006-01-02"), (*Identity).GetOver65, true},
		{"over65 no", now.AddDate(-64, 0, 0).Format("2006-01-02"), (*Identity).GetOver65, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := &Identity{BirthDate: tt.birthDate}
			got, err := tt.fn(id)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIdentity_GetOverAge_InvalidDate(t *testing.T) {
	id := &Identity{BirthDate: "invalid"}
	for _, fn := range []func(*Identity) (bool, error){
		(*Identity).GetOver16, (*Identity).GetOver18,
		(*Identity).GetOver21, (*Identity).GetOver65,
	} {
		_, err := fn(id)
		if err == nil {
			t.Error("expected error for invalid date")
		}
	}
}

func TestGetOpenID4VPAuth(t *testing.T) {
	t.Run("nil APIGW", func(t *testing.T) {
		cfg := &Cfg{}
		if cfg.GetOpenID4VPAuth("scope") != nil {
			t.Error("expected nil")
		}
	})

	t.Run("found", func(t *testing.T) {
		cfg := &Cfg{
			APIGW: &APIGW{
				DataSources: DataSources{
					Datastore: DatastoreConfig{
						Scopes: map[string]DatastoreScope{
							"test": {
								AuthProvider: AuthProviderOpenID4VP,
								AuthScopes: map[string]AuthScopeEntry{
									"openid": {AuthClaims: []string{"sub"}},
								},
							},
						},
					},
				},
			},
		}
		result := cfg.GetOpenID4VPAuth("test")
		if result == nil {
			t.Fatal("expected non-nil")
		}
		if len(result.AuthScopes) != 1 {
			t.Fatalf("expected 1 auth scope, got %d", len(result.AuthScopes))
		}
		entry, ok := result.AuthScopes["openid"]
		if !ok {
			t.Fatal("expected 'openid' key in AuthScopes")
		}
		if len(entry.AuthClaims) != 1 || entry.AuthClaims[0] != "sub" {
			t.Errorf("unexpected auth claims: %v", entry.AuthClaims)
		}
	})

	t.Run("wrong provider", func(t *testing.T) {
		cfg := &Cfg{
			APIGW: &APIGW{
				DataSources: DataSources{
					Datastore: DatastoreConfig{
						Scopes: map[string]DatastoreScope{
							"test": {AuthProvider: AuthProviderSAML},
						},
					},
				},
			},
		}
		if cfg.GetOpenID4VPAuth("test") != nil {
			t.Error("expected nil for non-openid4vp provider")
		}
	})

	t.Run("not found", func(t *testing.T) {
		cfg := &Cfg{APIGW: &APIGW{}}
		if cfg.GetOpenID4VPAuth("missing") != nil {
			t.Error("expected nil")
		}
	})
}

func TestGetFormatForScope(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			CredentialMetadata: map[string]*CredentialMetadata{
				"pid": {Format: "vc+sd-jwt"},
			},
		},
	}

	if got := cfg.GetFormatForScope("pid"); got != "vc+sd-jwt" {
		t.Errorf("expected vc+sd-jwt, got %s", got)
	}
	if got := cfg.GetFormatForScope("missing"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestVCTIdentifiersForScopes(t *testing.T) {
	cfg := &Cfg{Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{}}}
	ids := cfg.VCTIdentifiersForScopes([]string{"a", "b"})
	if len(ids) != 0 {
		t.Errorf("expected empty, got %v", ids)
	}
}

func TestOpenID4VPConfig_GetSupportedCredentials(t *testing.T) {
	var c *OpenID4VPConfig
	if c.GetSupportedCredentials() != nil {
		t.Error("expected nil for nil config")
	}

	c = &OpenID4VPConfig{
		SupportedCredentials: []SupportedCredentialConfig{{VCT: "urn:eudi:pid:1", Scopes: []string{"openid"}}},
	}
	if len(c.GetSupportedCredentials()) != 1 {
		t.Error("expected 1 credential")
	}
}

func TestOpenID4VPConfig_GetPresentationRequestsDir(t *testing.T) {
	var c *OpenID4VPConfig
	if c.GetPresentationRequestsDir() != "" {
		t.Error("expected empty for nil config")
	}

	c = &OpenID4VPConfig{PresentationRequestsDir: "/tmp/requests"}
	if c.GetPresentationRequestsDir() != "/tmp/requests" {
		t.Errorf("unexpected dir: %s", c.GetPresentationRequestsDir())
	}
}

// TestDCQLMetaQueryByFormat pins the meta constraint to the credential's
// FORMAT (OpenID4VP 1.0 6.4.1) rather than to whichever metadata document
// happens to be loaded.
//
// Both misreadings are represented below: an mso_mdoc scope that carries a
// VCTM (which a "has a VCTM?" test calls SD-JWT) and a registry-backed mdoc
// scope with a configured doctype and no MDDL (which a "has an MDDL?" test
// leaves unconstrained).
func TestDCQLMetaQueryByFormat(t *testing.T) {
	tests := []struct {
		name         string
		cm           *CredentialMetadata
		wantOK       bool
		wantVCTs     []string
		wantDoctype  string
		wantTypeVals [][]string
	}{
		{
			name:     "sd-jwt is constrained by its canonical vct",
			cm:       &CredentialMetadata{Format: openid4vp.FormatSDJWTVC, VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"}},
			wantOK:   true,
			wantVCTs: []string{"urn:eudi:pid:1"},
		},
		{
			// Still issued by this repo and treated as SD-JWT elsewhere.
			name:     "legacy vc+sd-jwt is treated as SD-JWT",
			cm:       &CredentialMetadata{Format: "vc+sd-jwt", VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"}},
			wantOK:   true,
			wantVCTs: []string{"urn:eudi:pid:1"},
		},
		{
			// Format's own `default:"dc+sd-jwt"`.
			name:     "empty format follows the declared default",
			cm:       &CredentialMetadata{VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"}},
			wantOK:   true,
			wantVCTs: []string{"urn:eudi:pid:1"},
		},
		{
			// Fallback for a scope whose MDDL never loaded.
			name:        "configured doctype is used when no MDDL is loaded",
			cm:          &CredentialMetadata{Format: openid4vp.FormatMsoMdoc, Doctype: "eu.europa.ec.eudi.pid.1"},
			wantOK:      true,
			wantDoctype: "eu.europa.ec.eudi.pid.1",
		},
		{
			// The MDDL wins: loadMDDLSchema fills it from the registry lookup
			// too, and IssuerMetadata advertises mddl.DocType in every case,
			// so the configured value is a source selector and not necessarily
			// the doctype the issued credential carries.
			name: "the loaded MDDL wins over a differing configured doctype",
			cm: &CredentialMetadata{
				Format:  openid4vp.FormatMsoMdoc,
				Doctype: "eu.europa.ec.eudi.pid.1",
				MDDL:    &mdoc.MDDLSchema{DocType: "org.iso.18013.5.1.mDL"},
			},
			wantOK:      true,
			wantDoctype: "org.iso.18013.5.1.mDL",
		},
		{
			// Routed by format, not by which document is loaded: a VCTM does
			// not make this an SD-JWT scope.
			name: "an mdoc carrying a VCTM is still an mdoc",
			cm: &CredentialMetadata{
				Format:  openid4vp.FormatMsoMdoc,
				Doctype: "org.iso.18013.5.1.mDL",
				VCTM:    &sdjwtvc.VCTM{VCT: "urn:something:else:1"},
			},
			wantOK:      true,
			wantDoctype: "org.iso.18013.5.1.mDL",
		},
		{
			// An mdoc carries a doctype and never a vct, and ResolveVCTUrls
			// may back-fill that vct from the hosting URL - so using it as a
			// doctype_value would ask for something no issued mdoc has.
			name:   "an mdoc with only a VCTM is unusable, not a vct query",
			cm:     &CredentialMetadata{Format: openid4vp.FormatMsoMdoc, VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"}},
			wantOK: false,
		},
		{
			name:   "an mdoc with no identifier at all is unusable",
			cm:     &CredentialMetadata{Format: openid4vp.FormatMsoMdoc},
			wantOK: false,
		},
		{
			// No credential_type_values: nothing to constrain by, and the bare
			// base type would match every W3C credential in the wallet.
			name:   "W3C with no configured type values is unusable",
			cm:     &CredentialMetadata{Format: "ldp_vc", VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"}},
			wantOK: false,
		},
		{
			name: "W3C is constrained by its configured type values",
			cm: &CredentialMetadata{
				Format:               "ldp_vc",
				CredentialTypeValues: [][]string{{baseVCTypeIRI, "https://example.org/diploma#DiplomaCredential"}},
			},
			wantOK:       true,
			wantTypeVals: [][]string{{baseVCTypeIRI, "https://example.org/diploma#DiplomaCredential"}},
		},
		{
			// Base-only narrows nothing, so it is dropped and nothing remains.
			name: "a base-only alternative is not a constraint",
			cm: &CredentialMetadata{
				Format:               "ldp_vc",
				CredentialTypeValues: [][]string{{baseVCTypeIRI}},
			},
			wantOK: false,
		},
		{
			// Reachable from a valid config: a map lookup that missed.
			name:   "nil receiver reports rather than panics",
			cm:     nil,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var meta openid4vp.MetaQuery
			var ok bool
			require.NotPanics(t, func() { meta, ok = tt.cm.DCQLMetaQuery() })
			assert.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				assert.Equal(t, openid4vp.MetaQuery{}, meta, "an unusable constraint must be empty, not partially filled")
				return
			}
			assert.Equal(t, tt.wantVCTs, meta.VCTValues)
			assert.Equal(t, tt.wantDoctype, meta.DoctypeValue)
			assert.Equal(t, tt.wantTypeVals, meta.TypeValues)
		})
	}
}

// TestVCTMRawWithVCTMalformed pins the refusal path. A JSON "null" unmarshals
// without error into a nil map, and assigning into one panics - which would
// take down issuance, not just config load, since the same helper runs there.
func TestVCTMRawWithVCTMalformed(t *testing.T) {
	for _, raw := range []string{"null", "[]", `"a string"`, "not json at all", ""} {
		t.Run(raw, func(t *testing.T) {
			got, changed := vctmRawWithVCT([]byte(raw), "https://apigw.example/type-metadata/pid")
			assert.False(t, changed, "an unrewritable document must be refused, not rewritten")
			assert.Equal(t, raw, string(got), "and handed back untouched")
		})
	}

	// And resolution survives one: the scope keeps its in-memory identifier
	// rather than panicking on the unrewritable bytes. loadVCTM refuses such
	// a document earlier, so this is the second line of defence.
	cm := &CredentialMetadata{
		Format: openid4vp.FormatSDJWTVC, VCTMFilePath: "/path/to/vctm.json",
		VCTM: &sdjwtvc.VCTM{}, VCTMRaw: []byte("null"),
	}
	cfg := &Cfg{Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{"pid": cm}}}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))
	assert.Equal(t, "https://apigw.example/type-metadata/pid", cm.GetVCTM().VCT)
	assert.Equal(t, "null", string(cm.GetVCTMRaw()), "unrewritable bytes are left alone")
}

// TestResolveVCTUrlsRejectsNilEntry pins the malformed-entry rule at the one
// place every consumer goes through.
//
// A present key holding nil is a config typo, not an absent scope. Left to
// each caller it is a panic waiting to happen - Client.New dereferences it
// during verifier startup, before any handler-level guard can run.
func TestResolveVCTUrlsRejectsNilEntry(t *testing.T) {
	cfg := &Cfg{Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{"broken": nil}}}
	err := cfg.ResolveVCTUrls("https://apigw.example")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken")
}

// TestReplaceVCT states what the option means, and what it deliberately does
// not touch.
//
// The served document ALWAYS declares a vct - one without it is not Type
// Metadata (SD-JWT VC 6.3), so there is no "publish it bare" case. What the
// option decides is whose identifier that is when the file brought its own:
// the file's by default, so a URN survives publication, or the hosting URL
// when this deployment owns the type.
func TestReplaceVCT(t *testing.T) {
	const hosted = "https://apigw.example/type-metadata/pid"

	localVCTM := func(vct string, replace *bool) *CredentialMetadata {
		raw := []byte(`{"name":"PID"}`)
		if vct != "" {
			raw = []byte(`{"vct":"` + vct + `","name":"PID"}`)
		}
		return &CredentialMetadata{
			Format:       openid4vp.FormatSDJWTVC,
			VCTMFilePath: "/path/to/vctm_pid.json",
			VCTM:         &sdjwtvc.VCTM{VCT: vct},
			VCTMRaw:      raw,
			ReplaceVCT:   replace,
		}
	}

	tests := []struct {
		name    string
		cm      *CredentialMetadata
		wantVCT string
	}{
		{"no vct in the file takes the hosting URL", localVCTM("", nil), hosted},
		{"and replace_vct changes nothing there", localVCTM("", new(true)), hosted},
		{"a declared urn is kept by default", localVCTM("urn:eudi:pid:1", nil), "urn:eudi:pid:1"},
		{"explicit false keeps it too", localVCTM("urn:eudi:pid:1", new(false)), "urn:eudi:pid:1"},
		{"replace_vct overwrites a declared urn", localVCTM("urn:eudi:pid:1", new(true)), hosted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Cfg{Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{"pid": tt.cm}}}
			require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"),
				"the option must never make a scope unloadable")

			// One identifier, four readers: the body, the query, the issuer
			// metadata, and the document served at the hosting URL.
			assert.Equal(t, tt.wantVCT, tt.cm.GetVCTM().VCT)
			assert.Equal(t, tt.wantVCT, tt.cm.vctIdentifier())

			meta, ok := tt.cm.DCQLMetaQuery()
			require.True(t, ok, "the scope stays requestable whatever the option says")
			assert.Equal(t, []string{tt.wantVCT}, meta.VCTValues)

			var served map[string]any
			require.NoError(t, json.Unmarshal(tt.cm.GetVCTMRaw(), &served))
			assert.Equal(t, tt.wantVCT, served["vct"],
				"the served document must declare the same identifier the credential names")
			assert.Equal(t, "PID", served["name"], "and keep the rest of the file")
		})
	}
}

// TestW3CTypes covers the issuance side: the compact-term list the issuer
// metadata advertises and issueVC20 mints from, whether it reads them back
// from that metadata or falls back to this directly.
//
// A verifier reads CredentialTypeValues instead. The asymmetry is deliberate:
// the representations differ (compact terms against fully expanded IRIs, not
// derivable from one another without JSON-LD expansion), and so does the bare
// base type - issuing a credential typed only "VerifiableCredential" is
// unspecific, while requesting one matches every W3C credential in the wallet.
func TestW3CTypes(t *testing.T) {
	tests := []struct {
		name string
		cm   *CredentialMetadata
		want []string
	}{
		{
			// Compact terms, as OID4VCI Appendix A.1 and the W3C VC data model
			// use them - not the expanded IRIs DCQL matches on.
			name: "configured types are used as written",
			cm:   &CredentialMetadata{CredentialTypes: []string{"VerifiableCredential", "DiplomaCredential"}},
			want: []string{"VerifiableCredential", "DiplomaCredential"},
		},
		{
			// What the issuer metadata always advertised.
			name: "unset falls back to the base type",
			cm:   &CredentialMetadata{},
			want: []string{"VerifiableCredential"},
		},
		{
			name: "nil receiver",
			cm:   nil,
			want: []string{"VerifiableCredential"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cm.W3CTypes())
		})
	}

	// A clone, so a caller cannot edit the configuration every later request
	// is built from.
	cm := &CredentialMetadata{CredentialTypes: []string{"VerifiableCredential", "DiplomaCredential"}}
	got := cm.W3CTypes()
	got[1] = "mutated"
	assert.Equal(t, []string{"VerifiableCredential", "DiplomaCredential"}, cm.CredentialTypes)
}

// TestW3CTypesAlwaysCarriesTheBaseType covers a review finding: the W3C VC data
// model requires every credential to carry VerifiableCredential, and a
// verifier's type_values alternatives name its IRI - so minting without it
// produces a credential that matches nothing.
func TestW3CTypesAlwaysCarriesTheBaseType(t *testing.T) {
	tests := []struct {
		name string
		cm   *CredentialMetadata
		want []string
	}{
		{"unset defaults to the base type", &CredentialMetadata{}, []string{baseVCType}},
		{"nil receiver too", nil, []string{baseVCType}},
		{
			"a config omitting the base type gets it prepended",
			&CredentialMetadata{CredentialTypes: []string{"DiplomaCredential"}},
			[]string{baseVCType, "DiplomaCredential"},
		},
		{
			"a config already naming it is left alone",
			&CredentialMetadata{CredentialTypes: []string{baseVCType, "DiplomaCredential"}},
			[]string{baseVCType, "DiplomaCredential"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cm.W3CTypes())
		})
	}
}

// TestCheckW3CTypeConsistency covers the other half: a scope configured to be
// requested by narrow types but issued as a bare VerifiableCredential can never
// match, so it is rejected at config load rather than at presentation time.
func TestCheckW3CTypeConsistency(t *testing.T) {
	diploma := [][]string{{baseVCTypeIRI, "https://example.org/diploma#DiplomaCredential"}}

	cfgWith := func(cm *CredentialMetadata) *Cfg {
		return &Cfg{Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{"diploma": cm}}}
	}

	err := cfgWith(&CredentialMetadata{Format: "ldp_vc", CredentialTypeValues: diploma}).checkW3CTypeConsistency()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "diploma")

	// Both halves configured: the ordinary case.
	assert.NoError(t, cfgWith(&CredentialMetadata{
		Format:               "ldp_vc",
		CredentialTypes:      []string{baseVCType, "DiplomaCredential"},
		CredentialTypeValues: diploma,
	}).checkW3CTypeConsistency())

	// Base-only credential_types mints the same bare credential as an absent
	// list, so it must be refused the same way.
	err = cfgWith(&CredentialMetadata{
		Format:               "ldp_vc",
		CredentialTypes:      []string{baseVCType},
		CredentialTypeValues: diploma,
	}).checkW3CTypeConsistency()
	require.Error(t, err)
	assert.Contains(t, err.Error(), baseVCType)

	// Issue-only is legitimate: the scope simply is not requestable.
	assert.NoError(t, cfgWith(&CredentialMetadata{
		Format:          "ldp_vc",
		CredentialTypes: []string{baseVCType, "DiplomaCredential"},
	}).checkW3CTypeConsistency())

	// A base-only alternative narrows nothing, so there is nothing to mismatch.
	assert.NoError(t, cfgWith(&CredentialMetadata{
		Format:               "ldp_vc",
		CredentialTypeValues: [][]string{{baseVCTypeIRI}},
	}).checkW3CTypeConsistency())

	// Not a W3C format.
	assert.NoError(t, cfgWith(&CredentialMetadata{Format: "dc+sd-jwt"}).checkW3CTypeConsistency())
}
