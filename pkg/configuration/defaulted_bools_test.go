package configuration

import (
	"reflect"
	"sort"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// A defaulted-true bool has to be a POINTER, or it can never be turned off.
//
// New unmarshals the YAML and then calls defaults.Set (config.go, the
// yaml.Unmarshal and defaults.Set pair). creasty/defaults fills any field
// still at its ZERO value - and the zero value of a bool is false, which is
// exactly what an operator writes to disable something. So with a plain
// bool, "fail_open: false" and "no fail_open key" are the same thing and
// both become true.
//
// The comment at that call site used to say explicit YAML values are never
// overwritten. True for a string or an int, where the zero value is not a
// value anyone means; false for a bool, where it is the only other value
// there is (SUNET/vc#753).
//
// This runs the loader's two steps over the real model.Cfg with the real
// library rather than calling New, which would need a complete, valid
// verifier config including VCTM files to get far enough to look.
func TestDefaultedBoolsSurviveAnExplicitFalse(t *testing.T) {
	raw := []byte(`
verifier:
  revocation:
    enabled: true
    fail_open: false
  outbound:
    oidc_provider:
      enable_userinfo: false
`)

	cfg := &model.Cfg{}
	require.NoError(t, yaml.Unmarshal(raw, cfg))
	require.NoError(t, defaults.Set(cfg))

	assert.False(t, model.BoolVal(cfg.Verifier.Revocation.FailOpen, true),
		"fail_open: false must survive defaults.Set - a verifier told to fail CLOSED on an unreachable status list was failing open")
	assert.False(t, model.BoolVal(cfg.Verifier.Outbound.OIDCProvider.EnableUserInfo, true),
		"enable_userinfo: false must survive defaults.Set")
}

// ... and saying nothing still gets the documented default, so the fix is
// not "both flags are now off".
func TestDefaultedBoolsStillDefaultToTrue(t *testing.T) {
	raw := []byte(`
verifier:
  revocation:
    enabled: true
  outbound:
    oidc_provider:
      issuer: https://verifier.example.org
`)

	cfg := &model.Cfg{}
	require.NoError(t, yaml.Unmarshal(raw, cfg))
	require.NoError(t, defaults.Set(cfg))

	assert.True(t, model.BoolVal(cfg.Verifier.Revocation.FailOpen, true),
		"an absent fail_open must still default to true")
	assert.True(t, model.BoolVal(cfg.Verifier.Outbound.OIDCProvider.EnableUserInfo, true),
		"an absent enable_userinfo must still default to true")
}

// Every other defaulted-true bool in the config is already a pointer
// (Production, AllowQRFallback, AutoAttempt, ShowClaims). This is the
// guard that stops the next plain one being added: the two that were
// broken looked exactly like the four that work.
func TestNoPlainBoolCarriesADefaultOfTrue(t *testing.T) {
	for _, field := range defaultedTrueBoolFields(t) {
		t.Errorf("%s is a plain bool with default:\"true\"; it can never be set to false - make it a *bool and read it through model.BoolVal", field)
	}
}

// defaultedTrueBoolFields walks model.Cfg and returns every plain (non
// pointer) bool field carrying default:"true".
//
// Types rather than values, so it sees fields inside stanzas no test
// config populates. Recursion is bounded by remembering the struct types
// already walked, which also makes a self-referential config type safe.
func defaultedTrueBoolFields(t *testing.T) []string {
	t.Helper()

	var found []string
	seen := map[reflect.Type]bool{}

	var walk func(typ reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice ||
			typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true

		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			name := path + "." + field.Name
			if field.Type.Kind() == reflect.Bool && field.Tag.Get("default") == "true" {
				found = append(found, name)
				continue
			}
			walk(field.Type, name)
		}
	}

	walk(reflect.TypeOf(model.Cfg{}), "Cfg")
	sort.Strings(found)
	return found
}
