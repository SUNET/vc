package model

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/mdoc"
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

func TestVCTUrlsForScopes(t *testing.T) {
	cfg := &Cfg{Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{}}}
	urls := cfg.VCTUrlsForScopes([]string{"a", "b"})
	if len(urls) != 0 {
		t.Errorf("expected empty, got %v", urls)
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

// TestVCTQueryValues pins the rule that ends the finding-16/finding-18
// flip-flop (SUNET/vc#673): a DCQL meta.vct_values list carries BOTH
// identifiers a wallet might match a credential type by, never one.
func TestVCTQueryValues(t *testing.T) {
	tests := []struct {
		name string
		cm   *CredentialMetadata
		want []string
	}{
		{
			// The case the bug was about: a VCTM whose own vct is a URN while
			// the type-metadata URL is something else entirely. Picking either
			// one alone is what broke half the deployed wallets.
			name: "distinct vct and url yields both, credential's own vct first",
			cm: &CredentialMetadata{
				VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				VCTURL: "https://apigw.example/type-metadata/pid",
				Format: "dc+sd-jwt",
			},
			want: []string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"},
		},
		{
			// Every VCTM shipped in metadata/ has no "vct" field, so
			// ResolveVCTUrls back-fills it from the URL and the two collapse.
			// A one-element list is the correct answer here - it is a property
			// of the metadata, not a regression of this function.
			name: "back-filled vct equal to url collapses to one value",
			cm: &CredentialMetadata{
				VCTM:   &sdjwtvc.VCTM{VCT: "https://apigw.example/type-metadata/pid"},
				VCTURL: "https://apigw.example/type-metadata/pid",
				Format: "dc+sd-jwt",
			},
			want: []string{"https://apigw.example/type-metadata/pid"},
		},
		{
			name: "no VCTM falls back to the url alone",
			cm: &CredentialMetadata{
				VCTURL: "https://apigw.example/type-metadata/pid",
				Format: "dc+sd-jwt",
			},
			want: []string{"https://apigw.example/type-metadata/pid"},
		},
		{
			// mso_mdoc is constrained by doctype_value, not vct_values.
			name: "mdoc scope contributes nothing",
			cm:   &CredentialMetadata{Format: "mso_mdoc"},
			want: nil,
		},
		{
			// Callers hand this the result of a map lookup that may have missed.
			name: "nil receiver",
			cm:   nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cm.VCTQueryValues())
		})
	}
}

// TestVCTQueryValuesForScopes covers the Cfg-level union: scope order is
// preserved, values shared between scopes appear once, and unknown or mdoc
// scopes contribute nothing rather than an empty string.
func TestVCTQueryValuesForScopes(t *testing.T) {
	cfg := &Cfg{Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{
		"pid": {
			VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
			VCTURL: "https://apigw.example/type-metadata/pid",
			Format: "dc+sd-jwt",
		},
		"ehic": {
			VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
			VCTURL: "https://apigw.example/type-metadata/ehic",
			Format: "dc+sd-jwt",
		},
		// Shares pid's URN, to prove the union deduplicates across scopes.
		"pid_alias": {
			VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
			VCTURL: "https://apigw.example/type-metadata/pid",
			Format: "dc+sd-jwt",
		},
		"pid_mdoc": {Format: "mso_mdoc"},
	}}}

	want := []string{
		"urn:eudi:pid:1",
		"https://apigw.example/type-metadata/pid",
		"urn:eudi:ehic:1",
		"https://apigw.example/type-metadata/ehic",
	}
	assert.Equal(t, want, cfg.VCTQueryValuesForScopes([]string{"pid", "pid_alias", "ehic", "pid_mdoc", "nosuchscope"}))
	assert.Empty(t, cfg.VCTQueryValuesForScopes(nil))
}

// TestDCQLMetaQueryFollowsFormat pins the constraint to the credential's
// FORMAT rather than to which metadata document happens to be loaded. Keying
// off "is an MDDL present" routed every non-mdoc format - including the ldp_vc
// and jwt_vc_json credentials this stack can issue - into the SD-JWT branch and
// emitted vct_values, which ValidateCredentialQuery rejects for those formats.
func TestDCQLMetaQueryFollowsFormat(t *testing.T) {
	tests := []struct {
		name        string
		cm          *CredentialMetadata
		wantOK      bool
		wantVCTs    []string
		wantDoctype string
	}{
		{
			name: "sd-jwt gets both vct identifiers",
			cm: &CredentialMetadata{
				Format: "dc+sd-jwt",
				VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				VCTURL: "https://apigw.example/type-metadata/pid",
			},
			wantOK:   true,
			wantVCTs: []string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"},
		},
		{
			// Format is declared `default:"dc+sd-jwt"`, so an unset one means
			// sd-jwt rather than "unsupported".
			name: "empty format honours the dc+sd-jwt default",
			cm: &CredentialMetadata{
				VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				VCTURL: "https://apigw.example/type-metadata/pid",
			},
			wantOK:   true,
			wantVCTs: []string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"},
		},
		{
			name:        "mdoc gets doctype_value",
			cm:          &CredentialMetadata{Format: "mso_mdoc", MDDL: &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"}},
			wantOK:      true,
			wantDoctype: "eu.europa.ec.eudi.pid.1",
		},
		{
			// A registry-resolved mdoc scope configures the doctype directly
			// and may have no MDDL document in hand.
			name:        "mdoc falls back to the configured doctype",
			cm:          &CredentialMetadata{Format: "mso_mdoc", Doctype: "eu.europa.ec.eudi.pid.1"},
			wantOK:      true,
			wantDoctype: "eu.europa.ec.eudi.pid.1",
		},
		{
			name:        "zk mdoc is still constrained by doctype",
			cm:          &CredentialMetadata{Format: "mso_mdoc_zk", MDDL: &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"}},
			wantOK:      true,
			wantDoctype: "eu.europa.ec.eudi.pid.1",
		},
		{
			// The Copilot finding: these used to fall into the sd-jwt branch.
			name:   "ldp_vc reports no expressible constraint",
			cm:     &CredentialMetadata{Format: "ldp_vc", VCTM: &sdjwtvc.VCTM{VCT: "urn:credential:diploma:1"}, VCTURL: "https://apigw.example/type-metadata/diploma"},
			wantOK: false,
		},
		{
			name:   "jwt_vc_json reports no expressible constraint",
			cm:     &CredentialMetadata{Format: "jwt_vc_json", VCTM: &sdjwtvc.VCTM{VCT: "urn:credential:diploma:1"}, VCTURL: "https://apigw.example/type-metadata/diploma"},
			wantOK: false,
		},
		{
			name:   "mdoc with no doctype anywhere",
			cm:     &CredentialMetadata{Format: "mso_mdoc"},
			wantOK: false,
		},
		{
			name:   "sd-jwt with no identifier at all",
			cm:     &CredentialMetadata{Format: "dc+sd-jwt"},
			wantOK: false,
		},
		{
			// An auth scope or requested scope with no credential_metadata
			// entry: config validation never checks that auth_scopes keys
			// resolve, and every accessor takes a lock on the receiver, so an
			// unguarded call here panicked.
			name:   "nil metadata",
			cm:     nil,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.cm.DCQLMetaQuery()
			require.Equal(t, tt.wantOK, ok)
			if !ok {
				return
			}
			assert.Equal(t, tt.wantDoctype, got.DoctypeValue)
			assert.Equal(t, tt.wantVCTs, got.VCTValues)
		})
	}
}
