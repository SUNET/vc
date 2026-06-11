package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var version = "n/a"

func main() {
	versionFlag := flag.Bool("version", false, "print version and exit")
	issuer := flag.String("issuer", "https://jwt-issuer.example.com", "JWT issuer (iss claim)")
	audience := flag.String("audience", "https://apigw.example.com", "JWT audience (aud claim)")
	subject := flag.String("subject", "test-user@example.com", "JWT subject (sub claim)")
	email := flag.String("email", "", "email claim (defaults to subject)")
	eppn := flag.String("eppn", "", "eppn claim (eduPersonPrincipalName)")
	expiry := flag.Duration("expiry", 1*time.Hour, "token expiry duration")
	kid := flag.String("kid", "test-key-1", "key ID")
	jwtFile := flag.String("jwt-out", "token.jwt", "output file for the signed JWT")
	jwkFile := flag.String("jwk-out", "jwks.json", "output file for the JWKS (public keys)")
	privFile := flag.String("priv-out", "", "output file for the private JWK (optional)")
	privInFile := flag.String("priv-in", "", "input file for an existing private JWK (optional, generates new key if not set)")

	flag.Parse()

	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}

	if *email == "" {
		*email = *subject
	}

	var privJWK jwk.Key

	if *privInFile != "" {
		// Load existing private key from file
		privJSON, err := os.ReadFile(*privInFile)
		if err != nil {
			fatal("read private key file: %v", err)
		}
		privJWK, err = jwk.ParseKey(privJSON)
		if err != nil {
			fatal("parse private key: %v", err)
		}
		fmt.Printf("Private key loaded from %s\n", *privInFile)
	} else {
		// Generate ECDSA P-256 key pair
		rawKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fatal("generate key: %v", err)
		}
		privJWK, err = jwk.Import(rawKey)
		if err != nil {
			fatal("import private key: %v", err)
		}
	}

	if err := privJWK.Set(jwk.KeyIDKey, *kid); err != nil {
		fatal("set kid: %v", err)
	}
	if err := privJWK.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		fatal("set alg: %v", err)
	}
	if err := privJWK.Set(jwk.KeyUsageKey, "sig"); err != nil {
		fatal("set use: %v", err)
	}

	// Build public JWK
	pubJWK, err := jwk.PublicKeyOf(privJWK)
	if err != nil {
		fatal("public key: %v", err)
	}

	// Create JWKS (public)
	jwks := jwk.NewSet()
	if err := jwks.AddKey(pubJWK); err != nil {
		fatal("add key to set: %v", err)
	}

	// Write JWKS file
	jwksJSON, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		fatal("marshal jwks: %v", err)
	}
	if err := os.WriteFile(*jwkFile, jwksJSON, 0o600); err != nil {
		fatal("write jwks: %v", err)
	}
	fmt.Printf("JWKS written to %s\n", *jwkFile)

	// Write private key file (optional)
	if *privFile != "" {
		privJSON, err := json.MarshalIndent(privJWK, "", "  ")
		if err != nil {
			fatal("marshal private key: %v", err)
		}
		if err := os.WriteFile(*privFile, privJSON, 0o600); err != nil {
			fatal("write private key: %v", err)
		}
		fmt.Printf("Private JWK written to %s\n", *privFile)
	}

	// Build JWT
	now := time.Now()
	builder := jwt.New()
	mustSet(builder, jwt.IssuerKey, *issuer)
	mustSet(builder, jwt.AudienceKey, []string{*audience})
	mustSet(builder, jwt.SubjectKey, *subject)
	mustSet(builder, jwt.IssuedAtKey, now)
	mustSet(builder, jwt.ExpirationKey, now.Add(*expiry))
	mustSet(builder, jwt.NotBeforeKey, now.Add(-1*time.Minute))
	mustSet(builder, "email", *email)
	if *eppn != "" {
		mustSet(builder, "eppn", *eppn)
	}

	// Sign JWT
	signed, err := jwt.Sign(builder, jwt.WithKey(jwa.ES256(), privJWK))
	if err != nil {
		fatal("sign jwt: %v", err)
	}

	// Write JWT file
	if err := os.WriteFile(*jwtFile, signed, 0o600); err != nil {
		fatal("write jwt: %v", err)
	}
	fmt.Printf("JWT written to %s\n", *jwtFile)

	// Print summary
	fmt.Println()
	fmt.Println("--- Configuration ---")
	fmt.Printf("issuer:   %s\n", *issuer)
	fmt.Printf("audience: %s\n", *audience)
	fmt.Printf("subject:  %s\n", *subject)
	fmt.Printf("email:    %s\n", *email)
	if *eppn != "" {
		fmt.Printf("eppn:     %s\n", *eppn)
	}
	fmt.Printf("kid:      %s\n", *kid)
	fmt.Printf("expires:  %s\n", now.Add(*expiry).Format(time.RFC3339))
	fmt.Println()
	fmt.Println("--- Example apigw config ---")
	fmt.Println("api_server:")
	fmt.Println("  api_auth:")
	fmt.Println("    jwks:")
	fmt.Println("      enable: true")
	fmt.Printf("      jwks_file_path: \"%s\"\n", *jwkFile)
	fmt.Printf("      issuer: \"%s\"\n", *issuer)
	fmt.Printf("      audience: \"%s\"\n", *audience)
	fmt.Println()
	fmt.Println("--- Usage ---")
	fmt.Printf("curl -H \"Authorization: Bearer $(cat %s)\" https://apigw.example.com/api/v1/...\n", *jwtFile)
}

func mustSet(token jwt.Token, key string, value any) {
	if err := token.Set(key, value); err != nil {
		fatal("set %s: %v", key, err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
