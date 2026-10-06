package configuration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeKey(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "enc.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path
}

func p256KeyPath(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return writeKey(t, key)
}

func encryptionCfg(enc model.CredentialEncryption, legacy *openid4vci.MetadataCredentialResponseEncryption) *model.Cfg {
	return &model.Cfg{
		APIGW: &model.APIGW{
			IssuerMetadata: model.IssuerMetadata{
				CredentialEncryption:         enc,
				CredentialResponseEncryption: legacy,
			},
		},
	}
}

// The hand-written block used to publish algorithms nothing implemented.
// Refusing it, rather than ignoring it, is the point: an operator who wrote
// those algorithms down meant for responses to be encrypted.
func TestCheckCredentialEncryption_RefusesTheHandWrittenBlock(t *testing.T) {
	cfg := encryptionCfg(model.CredentialEncryption{}, &openid4vci.MetadataCredentialResponseEncryption{
		AlgValuesSupported: []string{"ECDH-ES"},
		EncValuesSupported: []string{"A256GCM"},
	})

	err := checkCredentialEncryption(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential_response_encryption")
	assert.Contains(t, err.Error(), "credential_encryption.keys")
}

// A key that cannot perform ECDH-ES must not become a 500 on a wallet's
// credential request.
func TestCheckCredentialEncryption_RefusesAKeyThatCannotDoECDH(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-key.pem")
	require.NoError(t, os.WriteFile(path, []byte("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n"), 0o600))

	err := checkCredentialEncryption(encryptionCfg(model.CredentialEncryption{
		Keys: []model.CredentialEncryptionKey{{PrivateKeyPath: path}},
	}, nil))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential_encryption")
}

// Requiring encryption without a key to do it with is a contradiction, and
// one that would otherwise refuse every request at runtime.
func TestCheckCredentialEncryption_RefusesRequiredWithoutAKey(t *testing.T) {
	required := true

	for name, enc := range map[string]model.CredentialEncryption{
		"request":  {RequestEncryptionRequired: &required},
		"response": {ResponseEncryptionRequired: &required},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkCredentialEncryption(encryptionCfg(enc, nil))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no encryption key is configured")
		})
	}
}

func TestCheckCredentialEncryption_Accepts(t *testing.T) {
	t.Run("no encryption at all", func(t *testing.T) {
		assert.NoError(t, checkCredentialEncryption(encryptionCfg(model.CredentialEncryption{}, nil)))
	})

	t.Run("a usable key", func(t *testing.T) {
		assert.NoError(t, checkCredentialEncryption(encryptionCfg(model.CredentialEncryption{
			Keys: []model.CredentialEncryptionKey{{PrivateKeyPath: p256KeyPath(t)}},
		}, nil)))
	})

	t.Run("two keys, for rotation", func(t *testing.T) {
		assert.NoError(t, checkCredentialEncryption(encryptionCfg(model.CredentialEncryption{
			Keys: []model.CredentialEncryptionKey{{PrivateKeyPath: p256KeyPath(t)}, {PrivateKeyPath: p256KeyPath(t)}},
		}, nil)))
	})

	t.Run("a service that is not the apigw", func(t *testing.T) {
		assert.NoError(t, checkCredentialEncryption(&model.Cfg{}))
	})
}

// The same key twice would publish two JWKs with one kid, so a wallet could
// not tell them apart.
func TestCheckCredentialEncryption_RefusesADuplicateKey(t *testing.T) {
	path := p256KeyPath(t)

	err := checkCredentialEncryption(encryptionCfg(model.CredentialEncryption{
		Keys: []model.CredentialEncryptionKey{{PrivateKeyPath: path}, {PrivateKeyPath: path}},
	}, nil))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}
