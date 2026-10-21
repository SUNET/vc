package helpers

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// DecodeBase64URL decodes a single unpadded base64url value.
//
// Shared because two services now load secrets written this way - the
// issuer's BBS keys and the apigw's seed derivation secrets - and a
// second copy of the leniency rules below is a second place for them to
// drift.
func DecodeBase64URL(value string) ([]byte, error) {
	// Trailing whitespace is what every editor and heredoc leaves behind;
	// padding is what a standard-base64 tool leaves behind. Neither is a
	// broken key.
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(value), "="))
	if err != nil {
		return nil, fmt.Errorf("not valid base64url: %w", err)
	}
	if len(decoded) == 0 {
		return nil, fmt.Errorf("is empty")
	}
	return decoded, nil
}

// ReadBase64URLFile reads a file holding a single base64url-encoded value.
func ReadBase64URLFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Trailing newlines are what every editor and every `echo -n`-less
	// pipeline leaves behind; rejecting them would be a needless trap.
	decoded, err := DecodeBase64URL(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s %w", path, err)
	}
	return decoded, nil
}
