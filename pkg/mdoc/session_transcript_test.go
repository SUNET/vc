package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestBuildOID4VPSessionTranscript_Structure(t *testing.T) {
	transcript, err := BuildOID4VPSessionTranscript("x509_san_dns:verifier.example", "nonce-1", "https://verifier.example/verification/oidc-direct_post", nil)
	if err != nil {
		t.Fatalf("BuildOID4VPSessionTranscript() error = %v", err)
	}

	var decoded []any
	if err := cbor.Unmarshal(transcript, &decoded); err != nil {
		t.Fatalf("failed to decode transcript: %v", err)
	}
	if len(decoded) != 3 {
		t.Fatalf("len(transcript) = %d, want 3", len(decoded))
	}
	if decoded[0] != nil {
		t.Errorf("transcript[0] (DeviceEngagementBytes) = %v, want nil", decoded[0])
	}
	if decoded[1] != nil {
		t.Errorf("transcript[1] (EReaderKeyBytes) = %v, want nil", decoded[1])
	}

	handover, ok := decoded[2].([]any)
	if !ok || len(handover) != 2 {
		t.Fatalf("transcript[2] (handover) = %v, want [handoverString, digest]", decoded[2])
	}
	if handover[0] != "OpenID4VPHandover" {
		t.Errorf("handover[0] = %v, want OpenID4VPHandover", handover[0])
	}
	digest, ok := handover[1].([]byte)
	if !ok || len(digest) != 32 {
		t.Errorf("handover[1] (digest) = %v, want 32 bytes", handover[1])
	}
}

func TestBuildOID4VPSessionTranscript_Deterministic(t *testing.T) {
	a, err := BuildOID4VPSessionTranscript("client", "nonce", "https://example.com/cb", nil)
	if err != nil {
		t.Fatalf("BuildOID4VPSessionTranscript() error = %v", err)
	}
	b, err := BuildOID4VPSessionTranscript("client", "nonce", "https://example.com/cb", nil)
	if err != nil {
		t.Fatalf("BuildOID4VPSessionTranscript() error = %v", err)
	}
	if string(a) != string(b) {
		t.Error("BuildOID4VPSessionTranscript() is not deterministic for identical inputs")
	}

	c, err := BuildOID4VPSessionTranscript("client", "different-nonce", "https://example.com/cb", nil)
	if err != nil {
		t.Fatalf("BuildOID4VPSessionTranscript() error = %v", err)
	}
	if string(a) == string(c) {
		t.Error("BuildOID4VPSessionTranscript() should differ when nonce differs")
	}
}
