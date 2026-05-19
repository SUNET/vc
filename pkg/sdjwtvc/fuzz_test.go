package sdjwtvc

import (
	"testing"
)

// FuzzTokenSplit fuzzes the SD-JWT token splitting logic.
// This is a security-critical parser that processes untrusted credential tokens.
func FuzzTokenSplit(f *testing.F) {
	// Real-world-like seeds
	f.Add("eyJ.eyJ.sig")
	f.Add("eyJ.eyJ.sig~disc1~disc2~")
	f.Add("eyJ.eyJ.sig~disc1~kb.jwt.here")
	f.Add("")
	f.Add("~")
	f.Add("~~~")
	f.Add("a.b.c~d~e~f.g.h")
	f.Add("....~....~....")
	f.Add(string(make([]byte, 1024)))

	f.Fuzz(func(t *testing.T, input string) {
		token := Token(input)
		header, body, sig, disclosures, kb, err := token.Split()
		if err != nil {
			return
		}
		// On success, the JWT parts must be non-empty
		if header == "" || body == "" || sig == "" {
			t.Fatal("Split succeeded but returned empty JWT parts")
		}
		_ = disclosures
		_ = kb
	})
}

// FuzzTokenParse fuzzes the full SD-JWT parse pipeline.
// Exercises base64 decoding, JSON unmarshaling, disclosure processing.
func FuzzTokenParse(f *testing.F) {
	f.Add("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig")
	f.Add("eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiYWJjIl19.sig~WyJzYWx0IiwiY2xhaW0iLCJ2YWx1ZSJd~")
	f.Add("")
	f.Add("not-base64.not-base64.sig")
	f.Add("eyB9.eyB9.sig") // base64("{}")

	f.Fuzz(func(t *testing.T, input string) {
		token := Token(input)
		parsed, err := token.Parse()
		if err != nil {
			return
		}
		if parsed == nil {
			t.Fatal("Parse returned nil without error")
		}
		if parsed.Claims == nil {
			t.Fatal("Parse returned nil claims without error")
		}
	})
}

// FuzzBase64Decode fuzzes the base64url decoder.
func FuzzBase64Decode(f *testing.F) {
	f.Add("aGVsbG8")
	f.Add("")
	f.Add("====")
	f.Add("not valid!")
	f.Add("dGVzdA")

	f.Fuzz(func(t *testing.T, input string) {
		_, _ = Base64Decode(input)
	})
}

// FuzzParseSelectiveDisclosure fuzzes disclosure parsing.
func FuzzParseSelectiveDisclosure(f *testing.F) {
	f.Add([]byte("WyJzYWx0IiwiY2xhaW0iLCJ2YWx1ZSJd")) // valid base64 of ["salt","claim","value"]

	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseSelectiveDisclosure([]string{string(input)})
	})
}
