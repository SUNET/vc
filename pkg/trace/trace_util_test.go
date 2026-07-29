package trace

import (
	"testing"
	"time"
)

func TestSafeAttr_NilValue(t *testing.T) {
	attr := SafeAttr("key", nil)
	if string(attr.Key) != "key.unsupported" {
		t.Errorf("expected key.unsupported, got %s", attr.Key)
	}
}

func TestSafeAttr_NilPointer(t *testing.T) {
	var s *string
	attr := SafeAttr("key", s)
	if string(attr.Key) != "key.unsupported" {
		t.Errorf("expected key.unsupported, got %s", attr.Key)
	}
}

func TestSafeAttr_String(t *testing.T) {
	s := "hello"
	attr := SafeAttr("key", &s)
	if attr.Value.AsString() != "hello" {
		t.Errorf("expected hello, got %s", attr.Value.AsString())
	}
}

func TestSafeAttr_Int(t *testing.T) {
	n := 42
	attr := SafeAttr("key", &n)
	if attr.Value.AsInt64() != 42 {
		t.Errorf("expected 42, got %d", attr.Value.AsInt64())
	}
}

func TestSafeAttr_Int64(t *testing.T) {
	n := int64(100)
	attr := SafeAttr("key", &n)
	if attr.Value.AsInt64() != 100 {
		t.Errorf("expected 100, got %d", attr.Value.AsInt64())
	}
}

func TestSafeAttr_Float64(t *testing.T) {
	f := 3.14
	attr := SafeAttr("key", &f)
	if attr.Value.AsFloat64() != 3.14 {
		t.Errorf("expected 3.14, got %f", attr.Value.AsFloat64())
	}
}

func TestSafeAttr_Bool(t *testing.T) {
	b := true
	attr := SafeAttr("key", &b)
	if attr.Value.AsBool() != true {
		t.Error("expected true")
	}
}

func TestSafeAttr_StringSlice(t *testing.T) {
	s := []string{"a", "b"}
	attr := SafeAttr("key", &s)
	got := attr.Value.AsStringSlice()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("unexpected slice: %v", got)
	}
}

func TestSafeAttr_IntSlice(t *testing.T) {
	s := []int{1, 2, 3}
	attr := SafeAttr("key", &s)
	got := attr.Value.AsInt64Slice()
	if len(got) != 3 {
		t.Errorf("expected 3 elements, got %d", len(got))
	}
}

func TestSafeAttr_Float64Slice(t *testing.T) {
	s := []float64{1.1, 2.2}
	attr := SafeAttr("key", &s)
	got := attr.Value.AsFloat64Slice()
	if len(got) != 2 {
		t.Errorf("expected 2 elements, got %d", len(got))
	}
}

func TestSafeAttr_BytesJSON(t *testing.T) {
	b := []byte(`{"key":"value"}`)
	attr := SafeAttr("key", &b)
	if attr.Value.AsString() != `{"key":"value"}` {
		t.Errorf("expected JSON string, got %s", attr.Value.AsString())
	}
}

func TestSafeAttr_BytesBinary(t *testing.T) {
	b := []byte{0xff, 0xfe}
	attr := SafeAttr("key", &b)
	// Should be base64 encoded
	if attr.Value.AsString() == "" {
		t.Error("expected non-empty base64 string")
	}
}

func TestSafeAttr_Time(t *testing.T) {
	tm := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	attr := SafeAttr("key", &tm)
	if attr.Value.AsString() != "2024-01-15T12:00:00Z" {
		t.Errorf("expected RFC3339, got %s", attr.Value.AsString())
	}
}

func TestSafeAttr_MapStringString(t *testing.T) {
	m := map[string]string{"a": "b"}
	attr := SafeAttr("key", &m)
	if attr.Value.AsString() != `{"a":"b"}` {
		t.Errorf("expected JSON map, got %s", attr.Value.AsString())
	}
}

func TestSafeAttr_UnsupportedType(t *testing.T) {
	n := 42
	attr := SafeAttr("key", n) // not a pointer
	if string(attr.Key) != "key.unsupported" {
		t.Errorf("expected key.unsupported, got %s", attr.Key)
	}
}

func TestIsPointer(t *testing.T) {
	s := "hello"
	if !isPointer(&s) {
		t.Error("expected true for pointer")
	}
	if isPointer(s) {
		t.Error("expected false for non-pointer")
	}
}

func FuzzSafeAttr(f *testing.F) {
	f.Add("key", "value")
	f.Add("", "")
	f.Add("k", "\x00\xff")

	f.Fuzz(func(t *testing.T, key, val string) {
		// Should never panic
		attr := SafeAttr(key, &val)
		if string(attr.Key) == "" && key != "" {
			t.Error("key should not be empty when input key is non-empty")
		}
		_ = attr.Value.AsString()
	})
}
