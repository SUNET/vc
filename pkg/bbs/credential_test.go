package bbs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// recordingIssuer stands in for the native side so the argument handling in
// [Issue] can be tested without cgo. It asserts nothing about BBS - the
// cgo-tagged tests do that against real vectors - only that what a caller
// passes arrives intact.
type recordingIssuer struct {
	got  IssueParams
	err  error
	jwp  string
	call int
}

func (r *recordingIssuer) Issue(p IssueParams) (string, error) {
	r.got = p
	r.call++
	return r.jwp, r.err
}

func TestIssueRequiresACommitmentAndAType(t *testing.T) {
	valid := IssueParams{
		Commitment:   []byte{1, 2, 3},
		Vct:          "https://example.test/id-card",
		DocumentData: json.RawMessage(`{"given_name":"Ada"}`),
	}

	for _, tc := range []struct {
		name   string
		mutate func(*IssueParams)
		want   string
	}{
		{"no commitment", func(p *IssueParams) { p.Commitment = nil }, "commitment is required"},
		{"empty commitment", func(p *IssueParams) { p.Commitment = []byte{} }, "commitment is required"},
		{"no vct", func(p *IssueParams) { p.Vct = "" }, "vct is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			tc.mutate(&p)
			issuer := &recordingIssuer{}
			_, err := Issue(issuer, p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.want)
			}
			// Rejected before anything reaches the signing key.
			if issuer.call != 0 {
				t.Fatal("a rejected request still reached the issuer")
			}
		})
	}
}

// The bound exists so a caller cannot dictate how much work the issuer
// does: message count drives generator derivation and proof size.
func TestIssueRejectsTooManyHolderPointers(t *testing.T) {
	pointers := make([]string, MaxMessages+1)
	for i := range pointers {
		pointers[i] = "/claim"
	}
	issuer := &recordingIssuer{}
	_, err := Issue(issuer, IssueParams{
		Commitment:     []byte{1},
		Vct:            "https://example.test/id-card",
		HolderPointers: pointers,
	})
	if err == nil || !strings.Contains(err.Error(), "over the") {
		t.Fatalf("err = %v, want one mentioning the limit", err)
	}
	if issuer.call != 0 {
		t.Fatal("an over-long request still reached the issuer")
	}
}

func TestIssuePassesEverythingThrough(t *testing.T) {
	want := IssueParams{
		Suite:          SuiteSchnorr,
		SecretKey:      []byte{9, 9},
		PublicKey:      []byte{8, 8},
		Commitment:     []byte{7, 7},
		Vct:            "https://example.test/id-card",
		DocumentData:   json.RawMessage(`{"given_name":"Ada"}`),
		HolderPointers: []string{"/device_pin_hash"},
		ExtraHeader:    json.RawMessage(`{"iss":"https://issuer.test"}`),
		KeyBinding:     SchnorrKeyBinding,
	}
	issuer := &recordingIssuer{jwp: "a.b.c"}
	got, err := Issue(issuer, want)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got != "a.b.c" {
		t.Fatalf("returned %q", got)
	}
	if issuer.got.Suite != want.Suite || issuer.got.Vct != want.Vct ||
		issuer.got.KeyBinding != want.KeyBinding ||
		string(issuer.got.DocumentData) != string(want.DocumentData) ||
		string(issuer.got.ExtraHeader) != string(want.ExtraHeader) ||
		len(issuer.got.HolderPointers) != 1 || issuer.got.HolderPointers[0] != "/device_pin_hash" {
		t.Fatalf("params were altered in transit: %+v", issuer.got)
	}
}

func TestIssuePropagatesTheIssuersError(t *testing.T) {
	sentinel := errors.New("native said no")
	_, err := Issue(&recordingIssuer{err: sentinel}, IssueParams{
		Commitment:   []byte{1},
		Vct:          "https://example.test/id-card",
		DocumentData: json.RawMessage(`{"given_name":"Ada"}`),
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the issuer's own", err)
	}
}

func TestDecodeCommitment(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	encoded := base64.RawURLEncoding.EncodeToString(raw)

	got, err := DecodeCommitment(encoded)
	if err != nil {
		t.Fatalf("DecodeCommitment: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("decoded %x, want %x", got, raw)
	}

	// Padded input is accepted too: the wire form is unpadded base64url,
	// but a client that pads is easy to be lenient about and impossible to
	// confuse with anything else.
	if _, err := DecodeCommitment(base64.URLEncoding.EncodeToString(raw)); err != nil {
		t.Fatalf("padded input: %v", err)
	}

	for _, bad := range []string{"", "not base64!", "///"} {
		if _, err := DecodeCommitment(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
