package primitives

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/google/uuid"
)

var randomNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// The default format is a version 4 UUID, and it is a real one: parsed back,
// with the version and variant bits a v4 must carry. A test that only
// checked the length would pass on 36 random characters.
func TestRandomDefaultsToAUUIDv4(t *testing.T) {
	out, err := apply(&RandomArgs{Output: claimpath.Keys("document_id")}, map[string]any{}, randomNow)
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
				out, err := apply(&RandomArgs{Output: claimpath.Keys("id"), Format: format}, map[string]any{}, randomNow)
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
			args:    RandomArgs{Output: claimpath.Keys("id"), Format: RandomFormatHex},
			decode:  hex.DecodeString,
			wantLen: defaultRandomBytes,
		},
		{
			name:    "hex honours bytes",
			args:    RandomArgs{Output: claimpath.Keys("id"), Format: RandomFormatHex, Bytes: 32},
			decode:  hex.DecodeString,
			wantLen: 32,
		},
		{
			name:    "base64url defaults to 16 bytes",
			args:    RandomArgs{Output: claimpath.Keys("id"), Format: RandomFormatBase64URL},
			decode:  base64.RawURLEncoding.DecodeString,
			wantLen: defaultRandomBytes,
		},
		{
			name:    "base64url honours bytes",
			args:    RandomArgs{Output: claimpath.Keys("id"), Format: RandomFormatBase64URL, Bytes: minRandomBytes},
			decode:  base64.RawURLEncoding.DecodeString,
			wantLen: minRandomBytes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := apply(&tt.args, map[string]any{}, randomNow)
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

	out, err := apply(&RandomArgs{Output: claimpath.Keys("document_id")}, claims, randomNow)
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
			out, err := apply(&RandomArgs{Output: claimpath.Keys("document_id")},
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
	out, err := apply(&RandomArgs{Output: claimpath.Keys("document_id"), Overwrite: true},
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

// A nested output nests, the same way every other primitive's does, so
// this can target a claim AttributeMapper materialised under a parent.
func TestRandomNestsADottedOutput(t *testing.T) {
	out, err := apply(&RandomArgs{Output: claimpath.Keys("identity", "document_id")}, map[string]any{}, randomNow)
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

	out, err := apply(&RandomArgs{Output: claimpath.Keys("identity", "document_id")}, claims, randomNow)
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
		"unknown format":   {Output: claimpath.Keys("id"), Format: "dice"},
		"too few bytes":    {Output: claimpath.Keys("id"), Format: RandomFormatHex, Bytes: minRandomBytes - 1},
		"too many bytes":   {Output: claimpath.Keys("id"), Format: RandomFormatHex, Bytes: maxRandomBytes + 1},
		"negative bytes":   {Output: claimpath.Keys("id"), Format: RandomFormatBase64URL, Bytes: -1},
		"output conflicts": {Output: claimpath.Keys("id", "sub"), Format: RandomFormatHex},
	} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{}
			if name == "output conflicts" {
				claims["id"] = "not a map"
			}
			if _, err := apply(&args, claims, randomNow); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}
}

// Bytes is ignored for uuid rather than refused: the format fixes the
// length, and a leftover setting from a format change should not stop
// issuance.
func TestRandomIgnoresBytesForUUID(t *testing.T) {
	out, err := apply(&RandomArgs{Output: claimpath.Keys("id"), Format: RandomFormatUUID, Bytes: maxRandomBytes},
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
	d := &Derivation{Random: &RandomArgs{Output: claimpath.Keys("document_id")}}

	if got := d.SelectedName(); got != "random" {
		t.Fatalf("SelectedName is %q, want \"random\"", got)
	}

	out, err := apply(d, map[string]any{}, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := uuid.Parse(out["document_id"].(string)); err != nil {
		t.Errorf("not a uuid: %v", err)
	}
}

// The clobber this guards against: writing ["id", "sub"] must not replace a
// scalar "id" that the source data really supplied.
func TestRandomRefusesToClobberAScalarParent(t *testing.T) {
	_, err := apply(&RandomArgs{Output: claimpath.Keys("id", "sub")}, map[string]any{"id": "ABC-123"}, randomNow)
	if err == nil {
		t.Fatal("want an error, got none")
	}
}

// An absent parent is not a conflict - that is the ordinary case, where the
// derivation creates the nesting.
func TestRandomCreatesAnAbsentParent(t *testing.T) {
	out, err := apply(&RandomArgs{Output: claimpath.Keys("a", "b", "c")}, map[string]any{}, randomNow)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	a := out["a"].(map[string]any)
	b := a["b"].(map[string]any)
	if _, err := uuid.Parse(b["c"].(string)); err != nil {
		t.Errorf("not a uuid: %v", err)
	}
}

// apply runs a primitive over JSON-based claims, writes its outputs into
// them as the derivation runner does, and returns the outputs by claim.
func apply(a Applier, claims map[string]any, now time.Time) (map[string]any, error) {
	shapes := Shapes{Source: claimpath.Nested(), Issued: claimpath.Nested()}
	working := NewWorking(claims, shapes)
	writes, err := a.Apply(working, now)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, w := range writes {
		if err := working.Write(w.Path, w.Value); err != nil {
			return nil, err
		}
		if err := shapes.Issued.Set(out, w.Path, w.Value); err != nil {
			return nil, err
		}
	}
	return out, nil
}
