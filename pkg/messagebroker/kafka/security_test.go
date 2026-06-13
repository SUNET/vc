package kafka

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTempCertAndKey generates a self-signed cert+key pair and writes them to dir.
// Returns (certPath, keyPath, caCertPath).
func writeTempCertAndKey(t *testing.T, dir string) (string, string, string) {
	t.Helper()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCertPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))

	// Generate client cert signed by CA
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "client.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o600))

	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))

	return certPath, keyPath, caCertPath
}

func TestApplySecurityConfig_NilConfig(t *testing.T) {
	sc := sarama.NewConfig()
	err := applySecurityConfig(sc, nil)
	require.NoError(t, err)
	assert.False(t, sc.Net.SASL.Enable)
	assert.False(t, sc.Net.TLS.Enable)
}

func TestApplySecurityConfig_NilCommon(t *testing.T) {
	sc := sarama.NewConfig()
	cfg := &model.Cfg{Common: nil}
	err := applySecurityConfig(sc, cfg)
	require.NoError(t, err)
	assert.False(t, sc.Net.SASL.Enable)
	assert.False(t, sc.Net.TLS.Enable)
}

func TestApplySecurityConfig_SASL_SCRAM256(t *testing.T) {
	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				SASL: &model.KafkaSASL{
					Enable:    true,
					Mechanism: "SCRAM-SHA-256",
					Username:  "user",
					Password:  "pass",
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.NoError(t, err)
	assert.True(t, sc.Net.SASL.Enable)
	assert.Equal(t, sarama.SASLMechanism(sarama.SASLTypeSCRAMSHA256), sc.Net.SASL.Mechanism)
	assert.Equal(t, "user", sc.Net.SASL.User)
	assert.Equal(t, "pass", sc.Net.SASL.Password)
	assert.NotNil(t, sc.Net.SASL.SCRAMClientGeneratorFunc)
}

func TestApplySecurityConfig_SASL_SCRAM512(t *testing.T) {
	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				SASL: &model.KafkaSASL{
					Enable:    true,
					Mechanism: "SCRAM-SHA-512",
					Username:  "u",
					Password:  "p",
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.NoError(t, err)
	assert.True(t, sc.Net.SASL.Enable)
	assert.Equal(t, sarama.SASLMechanism(sarama.SASLTypeSCRAMSHA512), sc.Net.SASL.Mechanism)
	assert.NotNil(t, sc.Net.SASL.SCRAMClientGeneratorFunc)
}

func TestApplySecurityConfig_SASL_PLAIN(t *testing.T) {
	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				SASL: &model.KafkaSASL{
					Enable:    true,
					Mechanism: "PLAIN",
					Username:  "u",
					Password:  "p",
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.NoError(t, err)
	assert.True(t, sc.Net.SASL.Enable)
	assert.Equal(t, sarama.SASLMechanism(sarama.SASLTypePlaintext), sc.Net.SASL.Mechanism)
}

func TestApplySecurityConfig_SASL_UnsupportedMechanism(t *testing.T) {
	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				SASL: &model.KafkaSASL{
					Enable:    true,
					Mechanism: "OAUTHBEARER",
					Username:  "u",
					Password:  "p",
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported SASL mechanism")
	assert.Contains(t, err.Error(), "OAUTHBEARER")
}

func TestApplySecurityConfig_SASL_Disabled(t *testing.T) {
	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				SASL: &model.KafkaSASL{
					Enable:    false,
					Mechanism: "SCRAM-SHA-512",
					Username:  "u",
					Password:  "p",
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.NoError(t, err)
	assert.False(t, sc.Net.SASL.Enable, "SASL should remain disabled when Enable=false")
}

func TestApplySecurityConfig_MTLS_Valid(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, caCertPath := writeTempCertAndKey(t, dir)

	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				MTLS: model.MTLS{
					Enable:       true,
					CACertPath:   caCertPath,
					CertFilePath: certPath,
					KeyFilePath:  keyPath,
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.NoError(t, err)
	assert.True(t, sc.Net.TLS.Enable)
	require.NotNil(t, sc.Net.TLS.Config)
	assert.NotNil(t, sc.Net.TLS.Config.RootCAs)
	assert.Len(t, sc.Net.TLS.Config.Certificates, 1)
	assert.False(t, sc.Net.TLS.Config.InsecureSkipVerify)
}

func TestApplySecurityConfig_MTLS_NoCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := writeTempCertAndKey(t, dir)

	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				MTLS: model.MTLS{
					Enable:       true,
					CACertPath:   "", // no CA — uses system roots
					CertFilePath: certPath,
					KeyFilePath:  keyPath,
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.NoError(t, err)
	assert.True(t, sc.Net.TLS.Enable)
	assert.Nil(t, sc.Net.TLS.Config.RootCAs, "RootCAs should be nil when no CA path is given")
	assert.Len(t, sc.Net.TLS.Config.Certificates, 1)
}

func TestApplySecurityConfig_MTLS_MissingCertPath(t *testing.T) {
	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				MTLS: model.MTLS{
					Enable:       true,
					CertFilePath: "",
					KeyFilePath:  "/some/key.pem",
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_file_path and key_file_path must both be set")
}

func TestApplySecurityConfig_MTLS_MissingKeyPath(t *testing.T) {
	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				MTLS: model.MTLS{
					Enable:       true,
					CertFilePath: "/some/cert.pem",
					KeyFilePath:  "",
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_file_path and key_file_path must both be set")
}

func TestApplySecurityConfig_MTLS_CACertNotFound(t *testing.T) {
	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				MTLS: model.MTLS{
					Enable:       true,
					CACertPath:   "/nonexistent/ca.pem",
					CertFilePath: "/some/cert.pem",
					KeyFilePath:  "/some/key.pem",
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading CA cert")
}

func TestApplySecurityConfig_MTLS_CACertInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "bad-ca.pem")
	require.NoError(t, os.WriteFile(badCA, []byte("not a valid PEM"), 0o600))

	certPath, keyPath, _ := writeTempCertAndKey(t, dir)

	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				MTLS: model.MTLS{
					Enable:       true,
					CACertPath:   badCA,
					CertFilePath: certPath,
					KeyFilePath:  keyPath,
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid certificates found")
}

func TestApplySecurityConfig_MTLS_InvalidKeyPair(t *testing.T) {
	dir := t.TempDir()
	_, _, caCertPath := writeTempCertAndKey(t, dir)

	// Write a cert but pair it with a different key
	certPath := filepath.Join(dir, "mismatch-cert.pem")
	keyPath := filepath.Join(dir, "mismatch-key.pem")

	// Generate a separate key (not matching the cert)
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Self-signed cert with key1
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "mismatch"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key1.PublicKey, key1)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600))

	// Write key2 (does not match cert)
	keyDER, err := x509.MarshalECPrivateKey(key2)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))

	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				MTLS: model.MTLS{
					Enable:       true,
					CACertPath:   caCertPath,
					CertFilePath: certPath,
					KeyFilePath:  keyPath,
				},
			},
		},
	}

	err = applySecurityConfig(sc, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading client cert/key")
}

func TestApplySecurityConfig_MTLS_InsecureSkipVerify(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := writeTempCertAndKey(t, dir)

	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				MTLS: model.MTLS{
					Enable:             true,
					CertFilePath:       certPath,
					KeyFilePath:        keyPath,
					InsecureSkipVerify: true,
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.NoError(t, err)
	assert.True(t, sc.Net.TLS.Config.InsecureSkipVerify)
}

func TestApplySecurityConfig_SASL_And_MTLS_Combined(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, caCertPath := writeTempCertAndKey(t, dir)

	sc := sarama.NewConfig()
	cfg := &model.Cfg{
		Common: &model.Common{
			Kafka: model.Kafka{
				SASL: &model.KafkaSASL{
					Enable:    true,
					Mechanism: "SCRAM-SHA-512",
					Username:  "user",
					Password:  "pass",
				},
				MTLS: model.MTLS{
					Enable:       true,
					CACertPath:   caCertPath,
					CertFilePath: certPath,
					KeyFilePath:  keyPath,
				},
			},
		},
	}

	err := applySecurityConfig(sc, cfg)
	require.NoError(t, err)
	assert.True(t, sc.Net.SASL.Enable)
	assert.Equal(t, sarama.SASLMechanism(sarama.SASLTypeSCRAMSHA512), sc.Net.SASL.Mechanism)
	assert.True(t, sc.Net.TLS.Enable)
	assert.Len(t, sc.Net.TLS.Config.Certificates, 1)
}
