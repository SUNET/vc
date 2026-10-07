package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/pki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The issuer metadata and the Credential Endpoint load this at different
// points in startup. If each read the files afresh, a secret rotated between
// those two moments would publish one public key while the endpoint kept the
// private half of another, and every JWE a wallet built from the metadata
// would be undecryptable.
func TestCredentialEncryptionLoadIsMemoized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enc.pem")
	writeEncryptionKey(t, path)

	cfg := &CredentialEncryption{Keys: []CredentialEncryptionKey{{PrivateKeyPath: path}}}

	first, err := cfg.Load()
	require.NoError(t, err)
	require.NotNil(t, first)
	firstJWKS := first.RequestMetadata().JWKS

	// The rotation: a different key, same path, between the two loads.
	writeEncryptionKey(t, path)

	second, err := cfg.Load()
	require.NoError(t, err)
	assert.Same(t, first, second, "both callers must get one instance")
	assert.JSONEq(t, string(firstJWKS), string(second.RequestMetadata().JWKS),
		"the published key must not change under the endpoint's feet")
}

// A failure is memoized too, so a second caller cannot be told the
// configuration is fine after the first was told it is not.
func TestCredentialEncryptionLoadMemoizesFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enc.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a key"), 0o600))

	cfg := &CredentialEncryption{Keys: []CredentialEncryptionKey{{PrivateKeyPath: path}}}

	_, firstErr := cfg.Load()
	require.Error(t, firstErr)

	writeEncryptionKey(t, path)

	_, secondErr := cfg.Load()
	require.Error(t, secondErr)
	assert.Equal(t, firstErr.Error(), secondErr.Error())
}

func writeEncryptionKey(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
}

// A key is held in one place. Both settings together is an operator who
// believes one of them is in force and cannot be told which, and neither is
// a key that does not exist; both are refused by name rather than left to
// surface as a missing file or an ignored stanza.
func TestCredentialEncryptionKeyNeedsExactlyOneSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enc.pem")
	writeEncryptionKey(t, path)

	hsm := &pki.PKCS11Config{
		ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
		KeyLabel:   "enc",
	}

	both := &CredentialEncryption{Keys: []CredentialEncryptionKey{{PrivateKeyPath: path, PKCS11: hsm}}}
	_, err := both.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not both")

	neither := &CredentialEncryption{Keys: []CredentialEncryptionKey{{}}}
	_, err = neither.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set either private_key_path or pkcs11")
}
