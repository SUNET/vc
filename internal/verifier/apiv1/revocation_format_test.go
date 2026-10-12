package apiv1

import "testing"

// TestFormatCanCarryStatus pins which formats a revocation check can read a
// status from.
//
// A ZK mDOC presentation proves statements about claims without revealing
// the document, so the verifier never sees an MSO and there is no status
// parameter. Treating that as "not revocable" - which is what happens if it
// falls through to the generic claims check, since the claims genuinely
// contain no status - lets a revoked credential verify.
func TestFormatCanCarryStatus(t *testing.T) {
	for format, want := range map[CredentialFormat]bool{
		FormatSDJWT:  true,
		FormatMDoc:   true,
		FormatMDocZK: false,
	} {
		if got := formatCanCarryStatus(format); got != want {
			t.Fatalf("formatCanCarryStatus(%q) = %v, want %v", format, got, want)
		}
	}
}
