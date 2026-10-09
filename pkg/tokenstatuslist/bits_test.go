package tokenstatuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestPackLayoutMatchesSpecExample pins the byte layout of Section 4.1 to the
// draft's own worked example: at bits=2 the statuses 0, 1, 2, 3 at indices
// 0..3 pack into the single byte 0b11100100, index 0 occupying the least
// significant bits.
func TestPackLayoutMatchesSpecExample(t *testing.T) {
	packed, err := Pack([]uint8{0, 1, 2, 3}, 2)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if len(packed) != 1 {
		t.Fatalf("expected 1 byte, got %d", len(packed))
	}
	const want = 0b11100100
	if packed[0] != want {
		t.Fatalf("packed byte = %08b, want %08b", packed[0], want)
	}
	got, err := Unpack(packed, 2)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	for i, want := range []uint8{0, 1, 2, 3} {
		if got[i] != want {
			t.Fatalf("index %d: got %d, want %d", i, got[i], want)
		}
	}
}

func TestPackUnpackRoundTrip(t *testing.T) {
	for _, bits := range []int{1, 2, 4, 8} {
		maxValue := 1<<bits - 1
		statuses := make([]uint8, 8/bits*3) // exactly three bytes worth
		for i := range statuses {
			statuses[i] = uint8(i % (maxValue + 1))
		}
		packed, err := Pack(statuses, bits)
		if err != nil {
			t.Fatalf("bits=%d Pack: %v", bits, err)
		}
		got, err := Unpack(packed, bits)
		if err != nil {
			t.Fatalf("bits=%d Unpack: %v", bits, err)
		}
		if len(got) != len(statuses) {
			t.Fatalf("bits=%d: got %d statuses, want %d", bits, len(got), len(statuses))
		}
		for i := range statuses {
			if got[i] != statuses[i] {
				t.Fatalf("bits=%d index %d: got %d, want %d", bits, i, got[i], statuses[i])
			}
		}
	}
}

// TestPackRefusesOversizedStatus: truncating a SUSPENDED (2) entry into a
// bits=1 list would publish it as VALID.
func TestPackRefusesOversizedStatus(t *testing.T) {
	if _, err := Pack([]uint8{StatusSuspended}, 1); err == nil {
		t.Fatal("expected Pack to refuse status 2 at bits=1")
	}
}

func TestBitsValidation(t *testing.T) {
	for _, bits := range []int{0, 3, 5, 6, 7, 9, 16, -1} {
		if ValidBits(bits) {
			t.Fatalf("ValidBits(%d) should be false", bits)
		}
		if _, err := Unpack([]byte{0x00}, bits); err == nil {
			t.Fatalf("Unpack should refuse bits=%d", bits)
		}
		if _, err := Pack([]uint8{0}, bits); err == nil {
			t.Fatalf("Pack should refuse bits=%d", bits)
		}
	}
}

// TestGetStatusFromJWTHonoursTokenBits is the regression test for the defect:
// a bits=1 Status List Token read at a hardcoded 8 bits returns a DIFFERENT
// credential's status rather than failing, so only a token whose width
// differs from the default can catch it.
func TestGetStatusFromJWTHonoursTokenBits(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// 128 entries at bits=1 compress to 16 bytes, so index 5 is in range
	// whether the reader honours bits or assumes 8. Index 5 is INVALID: at
	// bits=1 that is byte 0 bit 5, so a reader assuming bits=8 looks at byte
	// 5 instead, finds 0, and reports the credential VALID - wrong, silently,
	// with no error to notice. That silence is the whole defect.
	statuses := make([]uint8, 128)
	statuses[5] = StatusInvalid

	sl := New(statuses)
	sl.Bits = 1
	sl.Subject = "https://example.com/statuslists/1"
	sl.Issuer = "https://example.com"

	token, err := sl.GenerateJWT(JWTSigningConfig{SigningKey: key, SigningMethod: jwt.SigningMethodES256})
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	claims, err := ParseJWT(token, func(*jwt.Token) (any, error) { return &key.PublicKey, nil })
	if err != nil {
		t.Fatalf("ParseJWT: %v", err)
	}
	if claims.StatusList.Bits != 1 {
		t.Fatalf("token declared bits=%d, want 1", claims.StatusList.Bits)
	}

	got, err := GetStatusFromJWT(claims, 5)
	if err != nil {
		t.Fatalf("GetStatusFromJWT(5): %v", err)
	}
	if got != StatusInvalid {
		t.Fatalf("index 5: got status %d, want %d (INVALID)", got, StatusInvalid)
	}
	for _, idx := range []int{0, 1, 4, 6, 40, 127} {
		got, err := GetStatusFromJWT(claims, idx)
		if err != nil {
			t.Fatalf("GetStatusFromJWT(%d): %v", idx, err)
		}
		if got != StatusValid {
			t.Fatalf("index %d: got status %d, want VALID", idx, got)
		}
	}
}

// TestUnpackRefusesAnExpandingBomb: DecompressStatuses caps the
// DECOMPRESSED bytes, but unpacking expands them again - eight statuses per
// byte at bits=1 - so that cap alone does not bound the memory a decode
// costs. The input is a remotely supplied status list token.
func TestUnpackRefusesAnExpandingBomb(t *testing.T) {
	// One byte over what bits=1 may expand to.
	raw := make([]byte, maxUnpackedStatuses/8+1)
	if _, err := Unpack(raw, 1); err == nil {
		t.Fatal("Unpack accepted an input that expands past the status cap")
	}

	// The widest layout is unaffected: at bits=8 there is no expansion, so
	// the existing byte cap already bounds it.
	if _, err := Unpack(make([]byte, 1024), 8); err != nil {
		t.Fatalf("bits=8 must be unaffected: %v", err)
	}

	// And a list just inside the cap still decodes, so the guard is not
	// simply refusing everything.
	if _, err := Unpack(make([]byte, 1024), 1); err != nil {
		t.Fatalf("an ordinary bits=1 list must still decode: %v", err)
	}
}
