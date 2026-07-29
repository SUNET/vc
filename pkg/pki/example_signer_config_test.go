package pki_test

import (
	"context"
	"fmt"
	"log"

	"github.com/SUNET/vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
)

// ExampleSignerConfig_fileBasedSigning demonstrates using SignerConfig with file-based keys
func ExampleSignerConfig_fileBasedSigning() {
	// Create a signer config with file-based keys
	config := pki.NewSignerConfig(&pki.KeyConfig{
		PrivateKeyPath: "/path/to/private-key.pem",
		ChainPath:      "/path/to/certificate-chain.pem",
	})

	// Sign arbitrary data
	data := []byte("important data to sign")
	signature, err := config.Sign(data)
	if err != nil {
		log.Fatalf("failed to sign data: %v", err)
	}
	fmt.Printf("Signature length: %d bytes\n", len(signature))

	// Sign a JWT
	claims := jwt.MapClaims{
		"sub": "user123",
		"iss": "my-service",
		"exp": 1234567890,
	}
	token, err := config.SignJWT(claims)
	if err != nil {
		log.Fatalf("failed to sign JWT: %v", err)
	}
	fmt.Printf("JWT: %s\n", token)

	// Get public key as JWK
	jwk, err := config.GetJWK()
	if err != nil {
		log.Fatalf("failed to get JWK: %v", err)
	}
	fmt.Printf("JWK Algorithm: %s\n", jwk.Algorithm)
}

// ExampleSignerConfig_hsmSigning demonstrates using SignerConfig with HSM
func ExampleSignerConfig_hsmSigning() {
	// Create a signer config with HSM
	config := pki.NewSignerConfig(&pki.KeyConfig{
		PKCS11: &pki.PKCS11Config{
			ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
			PIN:        "1234",
			KeyLabel:   "signing-key",
		},
	})

	// Use the same interface for HSM-based signing
	claims := jwt.MapClaims{
		"sub": "user456",
		"iss": "secure-service",
	}
	token, err := config.SignJWT(claims)
	if err != nil {
		log.Fatalf("failed to sign JWT with HSM: %v", err)
	}
	fmt.Printf("HSM-signed JWT: %s\n", token)

	// Get certificate from HSM
	cert, err := config.GetCertificate()
	if err != nil {
		log.Fatalf("failed to get certificate: %v", err)
	}
	fmt.Printf("Certificate subject: %s\n", cert.Subject)
}

// ExampleSignerConfig_fallback demonstrates fallback from HSM to file
func ExampleSignerConfig_fallback() {
	// Configure with both HSM and file-based keys, preferring HSM
	config := pki.NewSignerConfig(&pki.KeyConfig{
		PrivateKeyPath: "/path/to/backup-key.pem",
		ChainPath:      "/path/to/backup-chain.pem",
		PKCS11: &pki.PKCS11Config{
			ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
			PIN:        "1234",
			KeyLabel:   "signing-key",
		},
		Priority:   []pki.KeySource{pki.KeySourceHSM, pki.KeySourceFile},
		EnableHSM:  true,
		EnableFile: true,
	})

	// Sign - will try HSM first, fall back to file if HSM fails
	data := []byte("data to sign")
	signature, err := config.Sign(data)
	if err != nil {
		log.Fatalf("failed to sign data: %v", err)
	}
	fmt.Printf("Signed with fallback: %d bytes\n", len(signature))
}

// ExampleSignerConfig_serviceUsage demonstrates typical service usage
func ExampleSignerConfig_serviceUsage() {
	// In a real service, this config would come from application config
	signerConfig := pki.NewSignerConfig(&pki.KeyConfig{
		PrivateKeyPath: "/etc/myservice/signing-key.pem",
		ChainPath:      "/etc/myservice/signing-chain.pem",
	})

	// Service method that needs to sign something
	generateAccessToken := func(userID string) (string, error) {
		claims := jwt.MapClaims{
			"sub": userID,
			"iss": "my-service",
			"iat": 1234567890,
			"exp": 1234571490,
		}
		return signerConfig.SignJWT(claims)
	}

	// Use in service
	token, err := generateAccessToken("user789")
	if err != nil {
		log.Fatalf("failed to generate token: %v", err)
	}
	fmt.Printf("Access token: %s\n", token)

	// Get public key for verification endpoint
	jwk, err := signerConfig.GetJWK()
	if err != nil {
		log.Fatalf("failed to get public key: %v", err)
	}
	fmt.Printf("Public key algorithm: %s\n", jwk.Algorithm)
}

// ExampleKeyMaterialSigner demonstrates using the Signer interface implementation
func ExampleKeyMaterialSigner() {
	// Load key material
	keyLoader := pki.NewKeyLoader()
	km, err := keyLoader.LoadKeyMaterial(&pki.KeyConfig{
		PrivateKeyPath: "/path/to/private-key.pem",
		ChainPath:      "/path/to/certificate-chain.pem",
	})
	if err != nil {
		log.Fatalf("failed to load key material: %v", err)
	}

	// Create a signer from the key material
	signer := pki.NewKeyMaterialSigner(km)

	// Sign data using the Signer interface
	ctx := context.Background()
	data := []byte("data to sign")
	signature, err := signer.Sign(ctx, data)
	if err != nil {
		log.Fatalf("failed to sign: %v", err)
	}

	fmt.Printf("Algorithm: %s\n", signer.Algorithm())
	fmt.Printf("Key ID: %s\n", signer.KeyID())
	fmt.Printf("Signature: %d bytes\n", len(signature))
}

// ExampleKeyMaterialSigner_withCredentials demonstrates using KeyMaterialSigner with credential issuance
func ExampleKeyMaterialSigner_withCredentials() {
	// Load signing key
	keyLoader := pki.NewKeyLoader()
	km, err := keyLoader.LoadKeyMaterial(&pki.KeyConfig{
		PrivateKeyPath: "/etc/issuer/signing-key.pem",
		ChainPath:      "/etc/issuer/chain.pem",
	})
	if err != nil {
		log.Fatalf("failed to load key: %v", err)
	}

	// Create signer implementing the Signer interface
	signer := pki.NewKeyMaterialSigner(km)

	// Function that requires a Signer interface (like credential issuance libraries)
	issueCredential := func(s pki.Signer, claims map[string]any) error {
		ctx := context.Background()
		// Credential issuance would use:
		// - s.Sign(ctx, data) for signing
		// - s.Algorithm() for JWT header
		// - s.KeyID() for kid claim
		// - s.PublicKey() for verification
		fmt.Printf("Issuing credential with key: %s\n", s.KeyID())
		fmt.Printf("Using algorithm: %s\n", s.Algorithm())

		// Example signing
		data := []byte("credential data")
		_, err := s.Sign(ctx, data)
		return err
	}

	// Pass the signer to credential issuance
	err = issueCredential(signer, map[string]any{
		"sub": "did:example:123",
		"vc": map[string]any{
			"type": []string{"VerifiableCredential"},
		},
	})
	if err != nil {
		log.Fatalf("failed to issue credential: %v", err)
	}
}
