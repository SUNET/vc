package jose_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/jose"
)

// makeTestJWT constructs a compact JWT from header and payload maps with a fake signature.
func makeTestJWT(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
}

func ExampleExtractClaim() {
	token := makeTestJWT(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		map[string]any{"sub": "user-123", "iss": "https://issuer.example.com"},
	)

	sub, err := jose.ExtractClaim(token, "sub")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("sub:", sub)

	iss, err := jose.ExtractClaim(token, "iss")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("iss:", iss)
	// Output:
	// sub: user-123
	// iss: https://issuer.example.com
}

func ExampleExtractClaim_missingClaim() {
	token := makeTestJWT(
		map[string]any{"alg": "ES256"},
		map[string]any{"sub": "user-123"},
	)

	_, err := jose.ExtractClaim(token, "nonexistent")
	fmt.Println("error:", err)
	// Output:
	// error: claim "nonexistent" not found
}

func ExampleExtractKIDFromCompactJWT() {
	token := makeTestJWT(
		map[string]any{"alg": "ES256", "kid": "key-abc-123"},
		map[string]any{"sub": "user"},
	)

	kid, err := jose.ExtractKIDFromCompactJWT(token)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("kid:", kid)
	// Output:
	// kid: key-abc-123
}

func ExampleExtractKIDFromCompactJWT_missing() {
	token := makeTestJWT(
		map[string]any{"alg": "ES256"},
		map[string]any{"sub": "user"},
	)

	_, err := jose.ExtractKIDFromCompactJWT(token)
	fmt.Println("error:", err)
	// Output:
	// error: kid not found in JWT header
}

func ExampleJWKS() {
	jwks := &jose.JWKS{
		Keys: []jose.JWKWithMetadata{
			{
				Kty: "EC",
				Crv: "P-256",
				Kid: "key-1",
				Alg: "ES256",
				Use: "sig",
				X:   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				Y:   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
			},
		},
	}

	fmt.Println("keys:", len(jwks.Keys))
	fmt.Println("kty:", jwks.Keys[0].Kty)
	fmt.Println("kid:", jwks.Keys[0].Kid)
	fmt.Println("alg:", jwks.Keys[0].Alg)
	fmt.Println("use:", jwks.Keys[0].Use)
	// Output:
	// keys: 1
	// kty: EC
	// kid: key-1
	// alg: ES256
	// use: sig
}

func ExampleParseJWK() {
	jwkMap := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
		"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		"kid": "my-key-id",
		"alg": "ES256",
	}

	jwk, err := jose.ParseJWK(jwkMap)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("kty:", jwk.Kty)
	fmt.Println("kid:", jwk.Kid)
	fmt.Println("crv:", jwk.Crv)
	// Output:
	// kty: EC
	// kid: my-key-id
	// crv: P-256
}
