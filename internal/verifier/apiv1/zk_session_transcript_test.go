package apiv1

import (
	"bytes"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
)

// The values below stand in for one session answered through either channel:
// same nonce, same reader key, because only the delivery path differs.
const (
	zkTestClientID    = "x509_san_dns:verifier.example.com"
	zkTestNonce       = "nonce-9f2c"
	zkTestResponseURI = "https://verifier.example.com/verification/direct_post"
	zkTestOrigin      = "https://verifier.example.com"
)

func zkTestThumbprint() []byte { return []byte{0x01, 0x02, 0x03, 0x04} }

// TestZKSessionTranscriptFollowsDeliveryChannel is the regression guard for
// the flag: dc_api=false must produce the OpenID4VPHandover and dc_api=true
// the OpenID4VPDCAPIHandover, byte for byte.
//
// Asserted against the builders rather than against golden bytes so this
// tracks the handover definitions instead of pinning a second copy of them;
// what it pins is the routing, which is what the flag decides.
func TestZKSessionTranscriptFollowsDeliveryChannel(t *testing.T) {
	tp := zkTestThumbprint()

	wantLink, err := mdoc.BuildOID4VPSessionTranscript(zkTestClientID, zkTestNonce, zkTestResponseURI, tp)
	if err != nil {
		t.Fatal(err)
	}
	wantDCAPI, err := mdoc.BuildOID4VPDCAPISessionTranscript(zkTestOrigin, zkTestNonce, tp)
	if err != nil {
		t.Fatal(err)
	}

	// Same inputs, so a swapped branch cannot pass by coincidence.
	if bytes.Equal(wantLink, wantDCAPI) {
		t.Fatal("the two handovers are identical, so this test cannot detect a swapped branch")
	}

	for _, tc := range []struct {
		name  string
		dcAPI bool
		want  []byte
	}{
		{name: "a link or QR response binds to the response URI and client_id", want: wantLink},
		{name: "a DC API response binds to the calling origin", dcAPI: true, want: wantDCAPI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := zkSessionTranscript(tc.dcAPI, zkTestOrigin, zkTestClientID, zkTestNonce, zkTestResponseURI, tp)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("wrong handover for dc_api=%v\n got: %x\nwant: %x", tc.dcAPI, got, tc.want)
			}
		})
	}
}

// TestZKSessionTranscriptBindsReaderKeyOnBothChannels covers the unbinding
// SUNET/vc#620 fixed for the link channel, on both channels.
//
// A dc_api.jwt response is always encrypted, so the DC API branch is the one
// where a dropped thumbprint is guaranteed to matter - and it would surface
// as a failed proof, not as a missing binding.
func TestZKSessionTranscriptBindsReaderKeyOnBothChannels(t *testing.T) {
	for _, dcAPI := range []bool{false, true} {
		with, err := zkSessionTranscript(dcAPI, zkTestOrigin, zkTestClientID, zkTestNonce, zkTestResponseURI, zkTestThumbprint())
		if err != nil {
			t.Fatal(err)
		}
		without, err := zkSessionTranscript(dcAPI, zkTestOrigin, zkTestClientID, zkTestNonce, zkTestResponseURI, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(with, without) {
			t.Fatalf("dc_api=%v: the reader key thumbprint does not reach the transcript, so the proof is unbound from the response encryption key", dcAPI)
		}

		other, err := zkSessionTranscript(dcAPI, zkTestOrigin, zkTestClientID, zkTestNonce, zkTestResponseURI, []byte{0xff, 0xfe})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(with, other) {
			t.Fatalf("dc_api=%v: a different reader key produced the same transcript", dcAPI)
		}
	}
}

// TestZKSessionTranscriptDCAPIRefusesEmptyOrigin pins the failure mode of the
// branch that has no fallback: the DC API handover binds to the calling
// origin, so building one without an origin would bind to nothing.
func TestZKSessionTranscriptDCAPIRefusesEmptyOrigin(t *testing.T) {
	if _, err := zkSessionTranscript(true, "", zkTestClientID, zkTestNonce, zkTestResponseURI, zkTestThumbprint()); err == nil {
		t.Fatal("expected an error for a DC API transcript with no origin")
	}

	// The link channel does not take an origin at all, so the same empty
	// value must be irrelevant there rather than fatal.
	if _, err := zkSessionTranscript(false, "", zkTestClientID, zkTestNonce, zkTestResponseURI, zkTestThumbprint()); err != nil {
		t.Fatalf("the link channel must not depend on the DC API origin: %v", err)
	}
}
