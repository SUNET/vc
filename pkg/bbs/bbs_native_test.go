//go:build bbsnative

package bbs

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// Driven by zk-cred-bbs's own reference vectors, staged by
// `make bbs-native-lib`. Using the crate's file rather than a copy kept
// here means the Go, Rust and TypeScript sides all check against the same
// ground truth and cannot drift apart.
//
// The `hardware_keybind` case additionally carries key binding signatures
// captured from a real YubiKey prototype, so a passing BlindSign here is
// agreement with hardware-produced data, not just internal consistency.
const vectorPath = "../../third_party/zk-cred-bbs/test-vectors/emlun_reference.json"

type vectors struct {
	HardwareKeybind struct {
		PK                  string   `json:"pk"`
		SK                  string   `json:"sk"`
		Header              string   `json:"header"`
		PresentationHeader  string   `json:"presentation_header"`
		SignerMessages      []string `json:"signer_messages"`
		CommittedMessages   []string `json:"committed_messages"`
		CommitmentWithProof string   `json:"commitment_with_proof"`
		Signature           string   `json:"signature"`
		Proof               string   `json:"proof"`
		Disclosures         []string `json:"disclosures"`
	} `json:"hardware_keybind"`
}

func load(t *testing.T) *vectors {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Skipf("reference vectors not staged (run `make bbs-native-lib`): %v", err)
	}
	v := &vectors{}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func decodeAll(t *testing.T, in []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(in))
	for i, s := range in {
		out[i] = unhex(t, s)
	}
	return out
}

func disclosures(t *testing.T, names []string) []Disclosure {
	t.Helper()
	out := make([]Disclosure, len(names))
	for i, n := range names {
		switch n {
		case "DISCLOSE":
			out[i] = Disclose
		case "HIDE":
			out[i] = Hide
		case "COMMIT":
			out[i] = Commit
		default:
			t.Fatalf("unknown disclosure %q", n)
		}
	}
	return out
}

func TestAvailableWithTag(t *testing.T) {
	if !Available() {
		t.Fatal("Available() must be true with the bbsnative tag")
	}
}

// The issuer path. The signature must match what the Rust and TypeScript
// implementations produce, byte for byte, across the C ABI.
func TestBlindSignMatchesReference(t *testing.T) {
	hw := load(t).HardwareKeybind

	got, err := Native().BlindSign(SuiteSchnorr,
		unhex(t, hw.SK), unhex(t, hw.PK),
		unhex(t, hw.CommitmentWithProof), unhex(t, hw.Header),
		decodeAll(t, hw.SignerMessages))
	if err != nil {
		t.Fatalf("BlindSign: %v", err)
	}
	if hex.EncodeToString(got) != hw.Signature {
		t.Fatalf("signature mismatch\n got: %s\nwant: %s", hex.EncodeToString(got), hw.Signature)
	}
}

// An issuer must refuse a commitment whose device proof of possession does
// not check out, rather than blind-signing it anyway. This is the check
// that stops a holder binding a credential to a key they do not control.
func TestBlindSignRejectsBadCommitment(t *testing.T) {
	hw := load(t).HardwareKeybind

	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"corrupted key binding signature", func(b []byte) { b[len(b)-1] ^= 0x01 }},
		{"corrupted commitment point", func(b []byte) { b[20] ^= 0x01 }},
		{"truncated", func(b []byte) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commitment := unhex(t, hw.CommitmentWithProof)
			if tc.name == "truncated" {
				commitment = commitment[:len(commitment)-1]
			} else {
				tc.mutate(commitment)
			}
			_, err := Native().BlindSign(SuiteSchnorr,
				unhex(t, hw.SK), unhex(t, hw.PK), commitment, unhex(t, hw.Header),
				decodeAll(t, hw.SignerMessages))
			if err == nil {
				t.Fatal("issuer signed a commitment it should have rejected")
			}
			if !errors.Is(err, ErrVerification) {
				t.Fatalf("want ErrVerification, got %v", err)
			}
		})
	}
}

func TestVerifyProof(t *testing.T) {
	hw := load(t).HardwareKeybind
	disc := disclosures(t, hw.Disclosures)

	all := append(decodeAll(t, hw.SignerMessages), decodeAll(t, hw.CommittedMessages)...)
	var disclosed [][]byte
	for i, m := range all {
		if disc[i] == Disclose {
			disclosed = append(disclosed, m)
		}
	}

	verify := func(proof []byte, ph []byte, known int) error {
		return Native().VerifyProof(SuiteSchnorr, unhex(t, hw.PK), proof,
			unhex(t, hw.Header), ph, known, disclosed, disc)
	}
	ph := unhex(t, hw.PresentationHeader)

	if err := verify(unhex(t, hw.Proof), ph, len(hw.SignerMessages)); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}

	t.Run("tampered proof", func(t *testing.T) {
		bad := unhex(t, hw.Proof)
		bad[len(bad)/2] ^= 0x01
		if err := verify(bad, ph, len(hw.SignerMessages)); err == nil {
			t.Fatal("a tampered proof was accepted")
		}
	})

	// Binding to the presentation header is what stops a captured proof
	// being replayed into a different session.
	t.Run("wrong presentation header", func(t *testing.T) {
		badPH := unhex(t, hw.PresentationHeader)
		badPH[0] ^= 0x01
		if err := verify(unhex(t, hw.Proof), badPH, len(hw.SignerMessages)); err == nil {
			t.Fatal("a proof verified against the wrong presentation header")
		}
	})

	// The issuer-known split decides which generator each message is bound
	// to, so lying about it must not verify.
	t.Run("wrong issuer-known count", func(t *testing.T) {
		if err := verify(unhex(t, hw.Proof), ph, len(hw.SignerMessages)-1); err == nil {
			t.Fatal("a proof verified with the wrong issuer-known count")
		}
	})
}

// An unknown suite must be an error, not a silent fallback to one the
// caller did not ask for — the suite selects domain separation, so a
// fallback would produce values that verify against nothing.
func TestUnknownSuiteIsRejected(t *testing.T) {
	hw := load(t).HardwareKeybind
	err := Native().VerifyProof(Suite(99), unhex(t, hw.PK), unhex(t, hw.Proof),
		nil, nil, 0, nil, nil)
	if err == nil {
		t.Fatal("an unknown suite selector was accepted")
	}
}
