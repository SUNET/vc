package zkvegaworker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two forms are alternatives, not a precedence question: getting the
// verifier key from somewhere other than where the caller meant is not a
// thing to resolve quietly, so both-set and neither-set are both malformed.
func TestVerifierKeyRequiresExactlyOneForm(t *testing.T) {
	t.Run("both set", func(t *testing.T) {
		_, err := (&Request{VerifierKeyPath: "/tmp/x", VerifierKeyBytes: []byte("y")}).VerifierKey()
		if err == nil || !strings.Contains(err.Error(), "both") {
			t.Fatalf("error = %v, want one refusing both forms at once", err)
		}
	})

	t.Run("neither set", func(t *testing.T) {
		_, err := (&Request{}).VerifierKey()
		if err == nil || !strings.Contains(err.Error(), "neither") {
			t.Fatalf("error = %v, want one refusing an empty request", err)
		}
	})
}

func TestVerifierKeyReadsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.vk")
	if err := os.WriteFile(path, []byte("verifier key bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := (&Request{VerifierKeyPath: path}).VerifierKey()
	if err != nil {
		t.Fatalf("VerifierKey() error = %v", err)
	}
	if string(got) != "verifier key bytes" {
		t.Errorf("VerifierKey() = %q, want the file's contents", got)
	}
}

func TestVerifierKeyStillAcceptsInlineBytes(t *testing.T) {
	got, err := (&Request{VerifierKeyBytes: []byte("inline")}).VerifierKey()
	if err != nil {
		t.Fatalf("VerifierKey() error = %v", err)
	}
	if string(got) != "inline" {
		t.Errorf("VerifierKey() = %q, want the inline bytes", got)
	}
}

// An evicted or truncated key must be an error here rather than an empty
// buffer handed to the native library, which would report something far
// less useful about the proof.
func TestVerifierKeyRefusesAnUnusableFile(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.vk")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{
		"missing":     filepath.Join(dir, "nope.vk"),
		"empty":       empty,
		"a directory": dir,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := (&Request{VerifierKeyPath: path}).VerifierKey(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
