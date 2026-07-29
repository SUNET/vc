package jose

import (
	"testing"
)

// FuzzParseJWTWithJWKHeader fuzzes JWT parsing with embedded JWK.
// This is a high-risk parser: it processes untrusted JWT tokens containing
// embedded keys — a common attack vector for key confusion attacks.
func FuzzParseJWTWithJWKHeader(f *testing.F) {
	f.Add("eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InRlc3QiLCJ5IjoidGVzdCJ9fQ.eyJzdWIiOiJ0ZXN0In0.sig")
	f.Add("")
	f.Add("not.a.jwt")
	f.Add("eyJ9.eyJ9.sig")
	f.Add("a]]]")

	f.Fuzz(func(t *testing.T, token string) {
		_, _, _, _, _ = ParseJWTWithJWKHeader(token)
	})
}

// FuzzParseX5CHeader fuzzes x5c certificate chain parsing from JWT headers.
// x5c headers contain base64-encoded DER certificates from untrusted tokens.
func FuzzParseX5CHeader(f *testing.F) {
	f.Add("dGVzdA==") // "test" in base64

	f.Fuzz(func(t *testing.T, input string) {
		// Test with single string
		_, _ = ParseX5CHeader(input)
		// Test with slice
		_, _ = ParseX5CHeader([]any{input})
	})
}
