package model

import (
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
		name        string
		cm          *CredentialMetadata
		wantOK      bool
		wantVCTs    []string
		wantDoctype string
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
			name:        "an mdoc carrying a VCTM is still an mdoc",
			cm:          &CredentialMetadata{Format: openid4vp.FormatMsoMdoc, VCTM: &sdjwtvc.VCTM{VCT: "org.iso.18013.5.1.mDL"}},
			wantOK:      true,
			wantDoctype: "org.iso.18013.5.1.mDL",
		},
		{
			name:   "an mdoc with no identifier at all is unusable",
			cm:     &CredentialMetadata{Format: openid4vp.FormatMsoMdoc},
			wantOK: false,
		},
		{
			// meta.type_values, which credential_metadata cannot supply yet.
			name:   "W3C has no expressible constraint",
			cm:     &CredentialMetadata{Format: "ldp_vc", VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"}},
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
			assert.Nil(t, meta.TypeValues)
		})
	}
}
