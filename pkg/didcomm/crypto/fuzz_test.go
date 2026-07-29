package crypto

import (
	"testing"
)

// FuzzParseSigningAlgorithm fuzzes the JWS algorithm parser.
func FuzzParseSigningAlgorithm(f *testing.F) {
	f.Add("EdDSA")
	f.Add("ES256")
	f.Add("ES256K")
	f.Add("ES384")
	f.Add("")
	f.Add("NONE")
	f.Add("none")
	f.Add("HS256")
	f.Add("RS256")

	f.Fuzz(func(t *testing.T, alg string) {
		_, _ = parseSigningAlgorithm(alg)
	})
}

// FuzzParseKeyAlgorithm fuzzes the JWE key algorithm parser.
func FuzzParseKeyAlgorithm(f *testing.F) {
	f.Add("ECDH-ES+A256KW")
	f.Add("ECDH-1PU+A256KW")
	f.Add("A256KW")
	f.Add("")
	f.Add("RSA-OAEP")

	f.Fuzz(func(t *testing.T, alg string) {
		_, _ = parseKeyAlgorithm(alg)
	})
}

// FuzzParseContentAlgorithm fuzzes the JWE content encryption algorithm parser.
func FuzzParseContentAlgorithm(f *testing.F) {
	f.Add("A256CBC-HS512")
	f.Add("A256GCM")
	f.Add("XC20P")
	f.Add("")
	f.Add("A128GCM")

	f.Fuzz(func(t *testing.T, enc string) {
		_, _ = parseContentAlgorithm(enc)
	})
}
