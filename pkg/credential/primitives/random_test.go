package primitives

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
)

var randomNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// The default format is a version 4 UUID, and it is a real one: parsed back,
// with the version and variant bits a v4 must carry. A test that only
// checked the length would pass on 36 random characters.
func TestRandomDefaultsToAUUIDv4(t *testing.T) {
	out, err := (&RandomArgs{Output: "document_id"}).Apply(map[string]any{}, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	value, ok := out["document_id"].(string)
	if !ok {
		t.Fatalf("document_id is %T, want string", out["document_id"])
	}

	parsed, err := uuid.Parse(value)
	if err != nil {
		t.Fatalf("parsing %q: %v", value, err)
	}
	if got := parsed.Version(); got != 4 {
		t.Errorf("version is %d, want 4", got)
	}
	if got := parsed.Variant(); got != uuid.RFC4122 {
		t.Errorf("variant is %v, want RFC4122", got)
	}
}

// The point of this primitive is that it is not a function of its input:
// two runs with identical claims must not agree.
func TestRandomIsDifferentEveryTime(t *testing.T) {
	for _, format := range []string{RandomFormatUUID, RandomFormatHex, RandomFormatBase64URL} {
		t.Run(format, func(t *testing.T) {
			seen := map[string]bool{}
			for range 50 {
				out, err := (&RandomArgs{Output: "id", Format: format}).Apply(map[string]any{}, randomNow)
				if err != nil {
					t.Fatalf("Apply: %v", err)
				}
				value := out["id"].(string)
				if seen[value] {
					t.Fatalf("%q came back twice", value)
				}
				seen[value] = true
			}
		})
	}
}

func TestRandomFormats(t *testing.T) {
	tests := []struct {
		name    string
		args    RandomArgs
		decode  func(string) ([]byte, error)
		wantLen int
	}{
		{
			name:    "hex defaults to 16 bytes",
			args:    RandomArgs{Output: "id", Format: RandomFormatHex},
			decode:  hex.DecodeString,
			wantLen: defaultRandomBytes,
		},
		{
			name:    "hex honours bytes",
			args:    RandomArgs{Output: "id", Format: RandomFormatHex, Bytes: 32},
			decode:  hex.DecodeString,
			wantLen: 32,
		},
		{
			name:    "base64url defaults to 16 bytes",
			args:    RandomArgs{Output: "id", Format: RandomFormatBase64URL},
			decode:  base64.RawURLEncoding.DecodeString,
			wantLen: defaultRandomBytes,
		},
		{
			name:    "base64url honours bytes",
			args:    RandomArgs{Output: "id", Format: RandomFormatBase64URL, Bytes: minRandomBytes},
			decode:  base64.RawURLEncoding.DecodeString,
			wantLen: minRandomBytes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.args.Apply(map[string]any{}, randomNow)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			decoded, err := tt.decode(out["id"].(string))
			if err != nil {
				t.Fatalf("decoding %q: %v", out["id"], err)
			}
			if len(decoded) != tt.wantLen {
				t.Errorf("decoded to %d bytes, want %d", len(decoded), tt.wantLen)
			}
		})
	}
}

// Replacing an identifier the source data really supplied is a worse
// failure than doing nothing, so the default fills only what is missing.
func TestRandomLeavesAnExistingValueAlone(t *testing.T) {
	claims := map[string]any{"document_id": "ABC-123"}

	out, err := (&RandomArgs{Output: "document_id"}).Apply(claims, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("produced %v, want nothing", out)
	}
	if claims["document_id"] != "ABC-123" {
		t.Errorf("the input claim was modified: %v", claims["document_id"])
	}
}

// A present-but-empty claim is what an attribute mapping's `default: ""`
// leaves behind, which is exactly the gap this primitive fills.
func TestRandomTreatsABlankValueAsMissing(t *testing.T) {
	for name, existing := range map[string]any{
		"empty string":   "",
		"nil":            nil,
		"empty list":     []any{},
		"empty []string": []string{},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := (&RandomArgs{Output: "document_id"}).Apply(
				map[string]any{"document_id": existing}, randomNow)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if out["document_id"] == nil || out["document_id"] == "" {
				t.Fatalf("produced %v, want a generated value", out)
			}
		})
	}
}

func TestRandomOverwrite(t *testing.T) {
	out, err := (&RandomArgs{Output: "document_id", Overwrite: true}).Apply(
		map[string]any{"document_id": "ABC-123"}, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if out["document_id"] == "ABC-123" {
		t.Error("the existing value survived an explicit overwrite")
	}
	if _, err := uuid.Parse(out["document_id"].(string)); err != nil {
		t.Errorf("replacement is not a uuid: %v", err)
	}
}

// Dot-notation output nests, the same way every other primitive's does, so
// this can target a claim AttributeMapper materialised under a parent.
func TestRandomNestsADottedOutput(t *testing.T) {
	out, err := (&RandomArgs{Output: "identity.document_id"}).Apply(map[string]any{}, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	identity, ok := out["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity is %T, want a map", out["identity"])
	}
	if _, err := uuid.Parse(identity["document_id"].(string)); err != nil {
		t.Errorf("nested value is not a uuid: %v", err)
	}
}

// ... and the nested case respects an existing value too, which a
// top-level-only presence check would miss.
func TestRandomLeavesAnExistingNestedValueAlone(t *testing.T) {
	claims := map[string]any{"identity": map[string]any{"document_id": "ABC-123"}}

	out, err := (&RandomArgs{Output: "identity.document_id"}).Apply(claims, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("produced %v, want nothing", out)
	}
}

// Config validation rejects these, but Apply is reachable from callers that
// build a Derivation programmatically, so it refuses rather than emitting a
// value nobody asked for.
func TestRandomRefusesBadConfiguration(t *testing.T) {
	for name, args := range map[string]RandomArgs{
		"no output":        {Format: RandomFormatHex},
		"unknown format":   {Output: "id", Format: "dice"},
		"too few bytes":    {Output: "id", Format: RandomFormatHex, Bytes: minRandomBytes - 1},
		"too many bytes":   {Output: "id", Format: RandomFormatHex, Bytes: maxRandomBytes + 1},
		"negative bytes":   {Output: "id", Format: RandomFormatBase64URL, Bytes: -1},
		"output conflicts": {Output: "id.sub", Format: RandomFormatHex},
	} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{}
			if name == "output conflicts" {
				claims["id"] = "not a map"
			}
			if _, err := args.Apply(claims, randomNow); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}
}

// Bytes is ignored for uuid rather than refused: the format fixes the
// length, and a leftover setting from a format change should not stop
// issuance.
func TestRandomIgnoresBytesForUUID(t *testing.T) {
	out, err := (&RandomArgs{Output: "id", Format: RandomFormatUUID, Bytes: maxRandomBytes}).Apply(
		map[string]any{}, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := uuid.Parse(out["id"].(string)); err != nil {
		t.Errorf("not a uuid: %v", err)
	}
}

// The dispatcher finds it by name, which is what makes `random:` a usable
// key in a scope's derivations list.
func TestRandomIsDispatchedByName(t *testing.T) {
	d := &Derivation{Random: &RandomArgs{Output: "document_id"}}

	if got := d.SelectedName(); got != "random" {
		t.Fatalf("SelectedName is %q, want \"random\"", got)
	}

	out, err := d.Apply(map[string]any{}, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := uuid.Parse(out["document_id"].(string)); err != nil {
		t.Errorf("not a uuid: %v", err)
	}
}

// The clobber this guards against: without the parent check, generating
// into "id.sub" would have ApplyDerivations replace a scalar "id" that the
// source data really supplied.
func TestRandomRefusesToClobberAScalarParent(t *testing.T) {
	_, err := (&RandomArgs{Output: "id.sub"}).Apply(map[string]any{"id": "ABC-123"}, randomNow)
	if err == nil {
		t.Fatal("want an error, got none")
	}
}

// An absent parent is not a conflict - that is the ordinary case, where the
// derivation creates the nesting.
func TestRandomCreatesAnAbsentParent(t *testing.T) {
	out, err := (&RandomArgs{Output: "a.b.c"}).Apply(map[string]any{}, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	a := out["a"].(map[string]any)
	b := a["b"].(map[string]any)
	if _, err := uuid.Parse(b["c"].(string)); err != nil {
		t.Errorf("not a uuid: %v", err)
	}
}
