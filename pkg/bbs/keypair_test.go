package bbs

import (
	"errors"
	"testing"
)

// fakeDeriver stands in for the native backend on the paths that never
// reach it, so the width checks can be tested without the cgo build tag.
type fakeDeriver struct {
	pk     []byte
	err    error
	called *bool
}

func (f fakeDeriver) SkToPk([]byte) ([]byte, error) {
	if f.called != nil {
		*f.called = true
	}
	return f.pk, f.err
}

func TestKeyPairMatchesChecksWidthsBeforeDeriving(t *testing.T) {
	// Not pedantry: the common misconfiguration is the wrong file
	// altogether - a PEM, or the other issuer's key - and an error naming
	// the width beats one from inside the curve arithmetic.
	called := false
	deriver := fakeDeriver{pk: make([]byte, OctetPublicKeyLength), called: &called}

	for _, tc := range []struct {
		name   string
		sk, pk []byte
	}{
		{"secret too short", make([]byte, 31), make([]byte, OctetPublicKeyLength)},
		{"secret too long", make([]byte, 33), make([]byte, OctetPublicKeyLength)},
		{"public too short", make([]byte, OctetSecretKeyLength), make([]byte, 95)},
		{"public is a G1 point", make([]byte, OctetSecretKeyLength), make([]byte, 48)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := KeyPairMatches(deriver, tc.sk, tc.pk); err == nil {
				t.Fatal("must be rejected on width alone")
			}
		})
	}
	if called {
		t.Fatal("the deriver must not be reached for a wrong-width key")
	}
}

func TestKeyPairMatchesAcceptsAMatchAndRejectsAMismatch(t *testing.T) {
	sk := make([]byte, OctetSecretKeyLength)
	right := make([]byte, OctetPublicKeyLength)
	right[0] = 0xAB
	wrong := make([]byte, OctetPublicKeyLength)
	wrong[0] = 0xCD

	if err := KeyPairMatches(fakeDeriver{pk: right}, sk, right); err != nil {
		t.Fatalf("a matching pair must be accepted: %v", err)
	}
	if err := KeyPairMatches(fakeDeriver{pk: right}, sk, wrong); err == nil {
		t.Fatal("a public key the secret does not derive must be rejected")
	}
}

// A deriver that cannot answer is not a verdict on the pair, and must not
// read as one.
func TestKeyPairMatchesSurfacesADeriverFailure(t *testing.T) {
	sk := make([]byte, OctetSecretKeyLength)
	pk := make([]byte, OctetPublicKeyLength)
	sentinel := errors.New("backend exploded")

	err := KeyPairMatches(fakeDeriver{err: sentinel}, sk, pk)
	if err == nil {
		t.Fatal("a deriver failure must not pass as a match")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("the underlying failure should be reachable, got: %v", err)
	}
}
