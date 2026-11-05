// Package base64url reads keys and secrets written as one unpadded
// base64url value.
package base64url

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Decode decodes one base64url value, trimming surrounding whitespace and
// padding.
func Decode(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(value), "="))
	if err != nil {
		return nil, fmt.Errorf("not valid base64url: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("is empty")
	}
	return decoded, nil
}

// ReadFile decodes the file at path.
func ReadFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	decoded, err := Decode(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s %w", path, err)
	}
	return decoded, nil
}
