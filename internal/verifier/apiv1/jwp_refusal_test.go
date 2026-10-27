package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// realJWP is a BBS credential in JWP Compact Serialization, produced by
// zk-cred-bbs through pkg/bbs.Issue from the crate's own reference vectors
// (third_party/zk-cred-bbs/test-vectors/emlun_reference.json, hardware
// keybind case) with a status reference in its extra header. It is checked
// in rather than generated here because generating it needs the cgo
// `bbsnative` build and the staged static library, which a plain checkout
// does not have.
func realJWP(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/bbs_credential.jwp")
	require.NoError(t, err)
	return strings.TrimSpace(string(raw))
}

// TestRealJWPFixtureIsWhatItClaims asserts the fixture's own preconditions
// before anything is concluded from it. A fixture that had silently stopped
// being a JWP would make every assertion below vacuously true.
func TestRealJWPFixtureIsWhatItClaims(t *testing.T) {
	jwp := realJWP(t)

	parts := strings.Split(jwp, ".")
	require.Len(t, parts, 3, "a JWP in Compact Serialization has three segments")
	require.NotContains(t, jwp, "~", "and no tilde, which is what makes it collide with a plain JWT")

	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err, "the first segment must be base64url, or detection never reaches the header at all")

	var header map[string]any
	require.NoError(t, json.Unmarshal(decoded, &header))
	require.Equal(t, "BBS-MOD", header["alg"])
	require.Contains(t, header, "cmap", "cmap is what tells a JWP Issuer Header from a JOSE header")

	// The status reference this PR puts in the issuer header, where no
	// claims-reading extractor will ever find it.
	statusList, ok := header["status"].(map[string]any)["status_list"].(map[string]any)
	require.True(t, ok, "the fixture must carry a status reference, since that is the point")
	require.Equal(t, float64(42), statusList["idx"])
}

// TestJWPIsDetectedAsJWP: before this, a JWP was classified "vc+sd-jwt" -
// same three base64url segments, same absence of "~" - and was refused only
// because the SD-JWT parser could not unmarshal its payload segment. That
// is the parser's strictness doing the work, not a decision: loosen it and
// a JWP slides into a path that checks nothing about it, revocation
// included.
func TestJWPIsDetectedAsJWP(t *testing.T) {
	require.Equal(t, FormatJWP, detectCredentialFormat(realJWP(t)))
}

// TestJWPDetectionDoesNotCaptureOrdinaryJWTs is the other half: a plain JWT
// has the same silhouette, and misreading one as a JWP would refuse a
// credential this verifier can actually check.
func TestJWPDetectionDoesNotCaptureOrdinaryJWTs(t *testing.T) {
	enc := base64.RawURLEncoding
	jwt := enc.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." +
		enc.EncodeToString([]byte(`{"iss":"https://issuer.test"}`)) + ".c2ln"

	require.Equal(t, FormatSDJWT, detectCredentialFormat(jwt))
}

// TestIsJWPIssuerHeaderRejectsGarbage: detection decodes attacker-supplied
// bytes, so it has to survive them. A first segment that is not JSON, or is
// JSON but not an object, must come back "not a JWP" rather than panic -
// and then take the SD-JWT path, which is where it went before.
func TestIsJWPIssuerHeaderRejectsGarbage(t *testing.T) {
	for _, header := range []string{"", "not json", "[]", `"string"`, "null", `{"alg":"ES256"}`} {
		require.False(t, isJWPIssuerHeader([]byte(header)), "header %q must not read as a JWP", header)
	}
}
