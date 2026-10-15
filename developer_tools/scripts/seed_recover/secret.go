package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/SUNET/vc/pkg/model"
)

// seedSecret resolves the derivation secret the same way the issuer does,
// including refusing both forms at once - a tool that picked one where the
// issuer refuses would print pseudonyms the issuer never produced.
func seedSecret(src *model.SeedSource) ([]byte, error) {
	switch {
	case src.SecretPath != "" && src.Secret != "":
		return nil, fmt.Errorf("the seed source sets both secret_path and a secret in the secrets file; the issuer refuses that, so this does too")
	case src.SecretPath != "":
		raw, err := os.ReadFile(filepath.Clean(src.SecretPath))
		if err != nil {
			return nil, err
		}
		return decodeBase64URL(string(raw))
	case src.Secret != "":
		return decodeBase64URL(src.Secret)
	default:
		return nil, fmt.Errorf("the seed source sets neither secret_path nor a secret in the secrets file")
	}
}

func decodeBase64URL(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(value), "="))
	if err != nil {
		return nil, fmt.Errorf("the derivation secret is not valid base64url: %w", err)
	}
	return decoded, nil
}
