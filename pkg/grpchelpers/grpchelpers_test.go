package grpchelpers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"vc/pkg/model"
)

// TestNormalizeFingerprint tests the fingerprint normalization function
func TestNormalizeFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase hex",
			input:    "a1b2c3d4e5f6",
			expected: "a1b2c3d4e5f6",
		},
		{
			name:     "uppercase hex",
			input:    "A1B2C3D4E5F6",
			expected: "a1b2c3d4e5f6",
		},
		{
			name:     "with SHA256 prefix",
			input:    "SHA256:a1b2c3d4e5f6",
			expected: "a1b2c3d4e5f6",
		},
		{
			name:     "with sha256 prefix lowercase",
			input:    "sha256:a1b2c3d4e5f6",
			expected: "a1b2c3d4e5f6",
		},
		{
			name:     "with colons",
			input:    "a1:b2:c3:d4:e5:f6",
			expected: "a1b2c3d4e5f6",
		},
		{
			name:     "with SHA256 prefix and colons",
			input:    "SHA256:a1:b2:c3:d4:e5:f6",
			expected: "a1b2c3d4e5f6",
		},
		{
			name:     "with spaces",
			input:    "a1 b2 c3 d4 e5 f6",
			expected: "a1b2c3d4e5f6",
		},
		{
			name:     "mixed case with colons and prefix",
			input:    "SHA256:A1:B2:C3:D4:E5:F6",
			expected: "a1b2c3d4e5f6",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeFingerprint(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFormatFingerprint tests the fingerprint formatting function
func TestFormatFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard hex",
			input:    "a1b2c3d4e5f6",
			expected: "SHA256:a1:b2:c3:d4:e5:f6",
		},
		{
			name:     "odd length",
			input:    "a1b2c3d4e5f",
			expected: "SHA256:a1:b2:c3:d4:e5:f",
		},
		{
			name:     "single byte",
			input:    "ab",
			expected: "SHA256:ab",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "SHA256:",
		},
		{
			name:     "full SHA256 length",
			input:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			expected: "SHA256:a1:b2:c3:d4:e5:f6:a1:b2:c3:d4:e5:f6:a1:b2:c3:d4:e5:f6:a1:b2:c3:d4:e5:f6:a1:b2:c3:d4:e5:f6:a1:b2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatFingerprint(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCertFingerprint tests the certificate fingerprint calculation
func TestCertFingerprint(t *testing.T) {
	// Generate a test certificate
	cert := generateTestCert(t, "test-cert", nil, nil)

	fingerprint := CertFingerprint(cert)

	// Verify it's a valid hex string of correct length (SHA256 = 64 hex chars)
	assert.Len(t, fingerprint, 64)
	assert.Regexp(t, "^[a-f0-9]+$", fingerprint)

	// Verify consistency - same cert should produce same fingerprint
	fingerprint2 := CertFingerprint(cert)
	assert.Equal(t, fingerprint, fingerprint2)
}

// TestNewClientConn_Insecure tests creating an insecure client connection
func TestNewClientConn_Insecure(t *testing.T) {
	cfg := model.GRPCClientTLS{
		Addr: "localhost:50051",
		TLS:  false,
	}

	conn, err := NewClientConn(cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()
}

// TestNewClientConn_TLS_InvalidCA tests TLS client with invalid CA file
func TestNewClientConn_TLS_InvalidCA(t *testing.T) {
	cfg := model.GRPCClientTLS{
		Addr:       "localhost:50051",
		TLS:        true,
		CAFilePath: "/nonexistent/ca.pem",
	}

	conn, err := NewClientConn(cfg)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "failed to read CA certificate")
}

// TestNewClientConn_TLS_InvalidClientCert tests TLS client with invalid client cert
func TestNewClientConn_TLS_InvalidClientCert(t *testing.T) {
	cfg := model.GRPCClientTLS{
		Addr:         "localhost:50051",
		TLS:          true,
		CertFilePath: "/nonexistent/cert.pem",
		KeyFilePath:  "/nonexistent/key.pem",
	}

	conn, err := NewClientConn(cfg)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

// TestNewClientConn_TLS_ValidCerts tests TLS client with valid certificates
func TestNewClientConn_TLS_ValidCerts(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caCert, caKey := generateTestCA(t)
	caCertPath := writeCertToFile(t, tmpDir, "ca.pem", caCert)

	// Generate client cert signed by CA
	clientCert, clientKey := generateTestCertSignedByCA(t, "client", caCert, caKey)
	clientCertPath := writeCertToFile(t, tmpDir, "client.pem", clientCert)
	clientKeyPath := writeKeyToFile(t, tmpDir, "client-key.pem", clientKey)

	cfg := model.GRPCClientTLS{
		Addr:         "localhost:50051",
		TLS:          true,
		CAFilePath:   caCertPath,
		CertFilePath: clientCertPath,
		KeyFilePath:  clientKeyPath,
		ServerName:   "localhost",
	}

	conn, err := NewClientConn(cfg)
	require.NoError(t, err)
	require.NotNil(t, conn)
	defer conn.Close()
}

// TestNewClientConn_TLS_InvalidCAPEM tests TLS client with invalid PEM content
func TestNewClientConn_TLS_InvalidCAPEM(t *testing.T) {
	tmpDir := t.TempDir()

	// Write invalid PEM content
	caPath := filepath.Join(tmpDir, "invalid-ca.pem")
	err := os.WriteFile(caPath, []byte("not a valid PEM"), 0600)
	require.NoError(t, err)

	cfg := model.GRPCClientTLS{
		Addr:       "localhost:50051",
		TLS:        true,
		CAFilePath: caPath,
	}

	conn, err := NewClientConn(cfg)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")
}

// TestNewServerOptions_Disabled tests server options when TLS is disabled
func TestNewServerOptions_Disabled(t *testing.T) {
	cfg := model.GRPCServer{
		Addr: "localhost:0",
		TLS: model.GRPCTLS{
			Enabled: false,
		},
	}

	opts, err := NewServerOptions(cfg)
	require.NoError(t, err)
	assert.Nil(t, opts)
}

// TestNewServerOptions_InvalidCert tests server options with invalid certificate
func TestNewServerOptions_InvalidCert(t *testing.T) {
	cfg := model.GRPCServer{
		Addr: "localhost:0",
		TLS: model.GRPCTLS{
			Enabled:      true,
			CertFilePath: "/nonexistent/cert.pem",
			KeyFilePath:  "/nonexistent/key.pem",
		},
	}

	opts, err := NewServerOptions(cfg)
	assert.Error(t, err)
	assert.Nil(t, opts)
	assert.Contains(t, err.Error(), "failed to load server certificate")
}

// TestNewServerOptions_InvalidClientCA tests server options with invalid client CA
func TestNewServerOptions_InvalidClientCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate server cert
	serverCert, serverKey := generateTestCertAndKey(t, "server")
	serverCertPath := writeCertToFile(t, tmpDir, "server.pem", serverCert)
	serverKeyPath := writeKeyToFile(t, tmpDir, "server-key.pem", serverKey)

	cfg := model.GRPCServer{
		Addr: "localhost:0",
		TLS: model.GRPCTLS{
			Enabled:      true,
			CertFilePath: serverCertPath,
			KeyFilePath:  serverKeyPath,
			ClientCAPath: "/nonexistent/ca.pem",
		},
	}

	opts, err := NewServerOptions(cfg)
	assert.Error(t, err)
	assert.Nil(t, opts)
	assert.Contains(t, err.Error(), "failed to read client CA certificate")
}

// TestNewServerOptions_InvalidClientCAPEM tests server options with invalid client CA PEM
func TestNewServerOptions_InvalidClientCAPEM(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate server cert
	serverCert, serverKey := generateTestCertAndKey(t, "server")
	serverCertPath := writeCertToFile(t, tmpDir, "server.pem", serverCert)
	serverKeyPath := writeKeyToFile(t, tmpDir, "server-key.pem", serverKey)

	// Write invalid PEM content
	caPath := filepath.Join(tmpDir, "invalid-ca.pem")
	err := os.WriteFile(caPath, []byte("not a valid PEM"), 0600)
	require.NoError(t, err)

	cfg := model.GRPCServer{
		Addr: "localhost:0",
		TLS: model.GRPCTLS{
			Enabled:      true,
			CertFilePath: serverCertPath,
			KeyFilePath:  serverKeyPath,
			ClientCAPath: caPath,
		},
	}

	opts, err := NewServerOptions(cfg)
	assert.Error(t, err)
	assert.Nil(t, opts)
	assert.Contains(t, err.Error(), "failed to parse client CA certificate")
}

// TestNewServerOptions_ValidTLS tests server options with valid TLS config
func TestNewServerOptions_ValidTLS(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate server cert
	serverCert, serverKey := generateTestCertAndKey(t, "server")
	serverCertPath := writeCertToFile(t, tmpDir, "server.pem", serverCert)
	serverKeyPath := writeKeyToFile(t, tmpDir, "server-key.pem", serverKey)

	cfg := model.GRPCServer{
		Addr: "localhost:0",
		TLS: model.GRPCTLS{
			Enabled:      true,
			CertFilePath: serverCertPath,
			KeyFilePath:  serverKeyPath,
		},
	}

	opts, err := NewServerOptions(cfg)
	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Len(t, opts, 1) // Just TLS credentials, no interceptors
}

// TestNewServerOptions_ValidMTLS tests server options with valid mTLS config
func TestNewServerOptions_ValidMTLS(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caCert, _ := generateTestCA(t)
	caCertPath := writeCertToFile(t, tmpDir, "ca.pem", caCert)

	// Generate server cert
	serverCert, serverKey := generateTestCertAndKey(t, "server")
	serverCertPath := writeCertToFile(t, tmpDir, "server.pem", serverCert)
	serverKeyPath := writeKeyToFile(t, tmpDir, "server-key.pem", serverKey)

	cfg := model.GRPCServer{
		Addr: "localhost:0",
		TLS: model.GRPCTLS{
			Enabled:      true,
			CertFilePath: serverCertPath,
			KeyFilePath:  serverKeyPath,
			ClientCAPath: caCertPath,
		},
	}

	opts, err := NewServerOptions(cfg)
	require.NoError(t, err)
	require.NotNil(t, opts)
	assert.Len(t, opts, 1) // Just TLS credentials, no interceptors (no fingerprints)
}

// TestNewServerOptions_WithFingerprints tests server options with fingerprint allowlist
func TestNewServerOptions_WithFingerprints(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caCert, _ := generateTestCA(t)
	caCertPath := writeCertToFile(t, tmpDir, "ca.pem", caCert)

	// Generate server cert
	serverCert, serverKey := generateTestCertAndKey(t, "server")
	serverCertPath := writeCertToFile(t, tmpDir, "server.pem", serverCert)
	serverKeyPath := writeKeyToFile(t, tmpDir, "server-key.pem", serverKey)

	cfg := model.GRPCServer{
		Addr: "localhost:0",
		TLS: model.GRPCTLS{
			Enabled:      true,
			CertFilePath: serverCertPath,
			KeyFilePath:  serverKeyPath,
			ClientCAPath: caCertPath,
			AllowedClientFingerprints: map[string]string{
				"SHA256:a1:b2:c3:d4": "test-client",
			},
		},
	}

	opts, err := NewServerOptions(cfg)
	require.NoError(t, err)
	require.NotNil(t, opts)
	// TLS credentials + unary interceptor + stream interceptor
	assert.Len(t, opts, 3)
}

// TestVerifyClientFingerprint_NoPeer tests verification with no peer info
func TestVerifyClientFingerprint_NoPeer(t *testing.T) {
	ctx := t.Context()
	allowedFingerprints := map[string]string{"abc123": "test"}

	err := verifyClientFingerprint(ctx, allowedFingerprints)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "no peer info")
}

// TestVerifyClientFingerprint_NoTLSInfo tests verification with no TLS info
func TestVerifyClientFingerprint_NoTLSInfo(t *testing.T) {
	// Create context with peer but no TLS info
	ctx := peer.NewContext(t.Context(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})
	allowedFingerprints := map[string]string{"abc123": "test"}

	err := verifyClientFingerprint(ctx, allowedFingerprints)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "no TLS info")
}

// TestVerifyClientFingerprint_NoCert tests verification with no client certificate
func TestVerifyClientFingerprint_NoCert(t *testing.T) {
	// Create context with TLS info but no peer certificates
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		},
	}
	ctx := peer.NewContext(t.Context(), &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		AuthInfo: tlsInfo,
	})
	allowedFingerprints := map[string]string{"abc123": "test"}

	err := verifyClientFingerprint(ctx, allowedFingerprints)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "no client certificate")
}

// TestVerifyClientFingerprint_NotAllowed tests verification with cert not in allowlist
func TestVerifyClientFingerprint_NotAllowed(t *testing.T) {
	// Generate a test certificate
	cert := generateTestCert(t, "test-client", nil, nil)

	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}
	ctx := peer.NewContext(t.Context(), &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		AuthInfo: tlsInfo,
	})

	// Use a fingerprint that doesn't match
	allowedFingerprints := map[string]string{"0000000000000000000000000000000000000000000000000000000000000000": "other-client"}

	err := verifyClientFingerprint(ctx, allowedFingerprints)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Contains(t, st.Message(), "fingerprint not in allowlist")
}

// TestVerifyClientFingerprint_Allowed tests verification with cert in allowlist
func TestVerifyClientFingerprint_Allowed(t *testing.T) {
	// Generate a test certificate
	cert := generateTestCert(t, "test-client", nil, nil)
	fingerprint := CertFingerprint(cert)

	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}
	ctx := peer.NewContext(t.Context(), &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		AuthInfo: tlsInfo,
	})

	allowedFingerprints := map[string]string{fingerprint: "test-client"}

	err := verifyClientFingerprint(ctx, allowedFingerprints)
	require.NoError(t, err)
}

// TestFingerprintUnaryInterceptor tests the unary interceptor
func TestFingerprintUnaryInterceptor(t *testing.T) {
	// Generate a test certificate
	cert := generateTestCert(t, "test-client", nil, nil)
	fingerprint := CertFingerprint(cert)

	allowedFingerprints := map[string]string{fingerprint: "test-client"}
	interceptor := fingerprintUnaryInterceptor(allowedFingerprints)

	t.Run("allowed fingerprint", func(t *testing.T) {
		tlsInfo := credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		}
		ctx := peer.NewContext(t.Context(), &peer.Peer{
			Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			AuthInfo: tlsInfo,
		})

		handlerCalled := false
		handler := func(ctx context.Context, req any) (any, error) {
			handlerCalled = true
			return "response", nil
		}

		resp, err := interceptor(ctx, "request", &grpc.UnaryServerInfo{}, handler)
		require.NoError(t, err)
		assert.True(t, handlerCalled)
		assert.Equal(t, "response", resp)
	})

	t.Run("denied fingerprint", func(t *testing.T) {
		// Generate a different certificate
		otherCert := generateTestCert(t, "other-client", nil, nil)

		tlsInfo := credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{otherCert},
			},
		}
		ctx := peer.NewContext(t.Context(), &peer.Peer{
			Addr:     &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			AuthInfo: tlsInfo,
		})

		handlerCalled := false
		handler := func(ctx context.Context, req any) (any, error) {
			handlerCalled = true
			return "response", nil
		}

		resp, err := interceptor(ctx, "request", &grpc.UnaryServerInfo{}, handler)
		require.Error(t, err)
		assert.False(t, handlerCalled)
		assert.Nil(t, resp)
	})
}

// Helper functions for generating test certificates

func generateTestCertAndKey(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func generateTestCert(t *testing.T, cn string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	parent := template
	signingKey := key
	if caCert != nil && caKey != nil {
		parent = caCert
		signingKey = caKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signingKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func generateTestCertSignedByCA(t *testing.T, cn string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func writeCertToFile(t *testing.T, dir, filename string, cert *x509.Certificate) string {
	t.Helper()

	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	require.NoError(t, err)

	return path
}

func writeKeyToFile(t *testing.T, dir, filename string, key *ecdsa.PrivateKey) string {
	t.Helper()

	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	err = pem.Encode(f, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})
	require.NoError(t, err)

	return path
}

// TestIntegration_mTLS_FingerprintNotInAllowlist tests a real gRPC server/client scenario
// where the client has a valid certificate signed by the CA, but the fingerprint is not
// in the server's allowlist. The connection should be rejected with PermissionDenied.
func TestIntegration_mTLS_FingerprintNotInAllowlist(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caCert, caKey := generateTestCA(t)
	caCertPath := writeCertToFile(t, tmpDir, "ca.pem", caCert)

	// Generate server cert signed by CA
	serverCert, serverKey := generateTestCertSignedByCA(t, "localhost", caCert, caKey)
	serverCertPath := writeCertToFile(t, tmpDir, "server.pem", serverCert)
	serverKeyPath := writeKeyToFile(t, tmpDir, "server-key.pem", serverKey)

	// Generate client cert signed by CA (this is valid, CA will accept it)
	clientCert, clientKey := generateTestCertSignedByCA(t, "client", caCert, caKey)
	clientCertPath := writeCertToFile(t, tmpDir, "client.pem", clientCert)
	clientKeyPath := writeKeyToFile(t, tmpDir, "client-key.pem", clientKey)

	// Get the actual fingerprint of the client cert
	actualFingerprint := CertFingerprint(clientCert)
	t.Logf("Client cert fingerprint: %s", FormatFingerprint(actualFingerprint))

	// Create a DIFFERENT fingerprint for the allowlist (so client is NOT allowed)
	differentFingerprint := "0000000000000000000000000000000000000000000000000000000000000000"

	// Configure server with mTLS + fingerprint allowlist that does NOT include our client
	serverCfg := model.GRPCServer{
		Addr: "127.0.0.1:0",
		TLS: model.GRPCTLS{
			Enabled:      true,
			CertFilePath: serverCertPath,
			KeyFilePath:  serverKeyPath,
			ClientCAPath: caCertPath,
			AllowedClientFingerprints: map[string]string{
				differentFingerprint: "some-other-client",
			},
		},
	}

	serverOpts, err := NewServerOptions(serverCfg)
	require.NoError(t, err)

	// Add an unknown service handler that always succeeds
	// This allows any method call to reach the interceptor
	unknownHandler := func(srv any, stream grpc.ServerStream) error {
		return nil
	}
	serverOpts = append(serverOpts, grpc.UnknownServiceHandler(unknownHandler))

	// Start gRPC server
	server := grpc.NewServer(serverOpts...)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Stop()

	// Configure client with mTLS
	clientCfg := model.GRPCClientTLS{
		Addr:         listener.Addr().String(),
		TLS:          true,
		CAFilePath:   caCertPath,
		CertFilePath: clientCertPath,
		KeyFilePath:  clientKeyPath,
		ServerName:   "localhost",
	}

	conn, err := NewClientConn(clientCfg)
	require.NoError(t, err)
	defer conn.Close()

	// Make an RPC call to any method - the interceptor will reject it
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Use EmptyCall style invocation (nil request/response is fine for unknown handler)
	err = conn.Invoke(ctx, "/test.TestService/Ping", nil, nil)
	require.Error(t, err)

	// Verify it's a PermissionDenied error (from fingerprint check)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error, got: %v", err)
	assert.Equal(t, codes.PermissionDenied, st.Code(), "expected PermissionDenied, got %s: %s", st.Code(), st.Message())
	assert.Contains(t, st.Message(), "fingerprint not in allowlist")
}

// TestIntegration_mTLS_FingerprintInAllowlist tests a real gRPC server/client scenario
// where the client has a valid certificate AND the fingerprint IS in the allowlist.
// The RPC should succeed.
func TestIntegration_mTLS_FingerprintInAllowlist(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA
	caCert, caKey := generateTestCA(t)
	caCertPath := writeCertToFile(t, tmpDir, "ca.pem", caCert)

	// Generate server cert signed by CA
	serverCert, serverKey := generateTestCertSignedByCA(t, "localhost", caCert, caKey)
	serverCertPath := writeCertToFile(t, tmpDir, "server.pem", serverCert)
	serverKeyPath := writeKeyToFile(t, tmpDir, "server-key.pem", serverKey)

	// Generate client cert signed by CA
	clientCert, clientKey := generateTestCertSignedByCA(t, "client", caCert, caKey)
	clientCertPath := writeCertToFile(t, tmpDir, "client.pem", clientCert)
	clientKeyPath := writeKeyToFile(t, tmpDir, "client-key.pem", clientKey)

	// Get the actual fingerprint of the client cert and ADD it to allowlist
	actualFingerprint := CertFingerprint(clientCert)
	t.Logf("Client cert fingerprint: %s", FormatFingerprint(actualFingerprint))

	// Configure server with mTLS + fingerprint allowlist that INCLUDES our client
	serverCfg := model.GRPCServer{
		Addr: "127.0.0.1:0",
		TLS: model.GRPCTLS{
			Enabled:      true,
			CertFilePath: serverCertPath,
			KeyFilePath:  serverKeyPath,
			ClientCAPath: caCertPath,
			AllowedClientFingerprints: map[string]string{
				actualFingerprint: "allowed-client",
			},
		},
	}

	serverOpts, err := NewServerOptions(serverCfg)
	require.NoError(t, err)

	// Track if handler was called (proves fingerprint check passed)
	handlerCalled := false

	// Add an unknown service handler that tracks if it was called
	unknownHandler := func(srv any, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}
	serverOpts = append(serverOpts, grpc.UnknownServiceHandler(unknownHandler))

	// Start gRPC server
	server := grpc.NewServer(serverOpts...)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Stop()

	// Configure client with mTLS
	clientCfg := model.GRPCClientTLS{
		Addr:         listener.Addr().String(),
		TLS:          true,
		CAFilePath:   caCertPath,
		CertFilePath: clientCertPath,
		KeyFilePath:  clientKeyPath,
		ServerName:   "localhost",
	}

	conn, err := NewClientConn(clientCfg)
	require.NoError(t, err)
	defer conn.Close()

	// Make an RPC call - fingerprint check should pass and handler should be called
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	err = conn.Invoke(ctx, "/test.TestService/Ping", nil, nil)

	// The unknown handler returns nil but doesn't send a response message,
	// so we get an "Internal" error about no response. But that's OK -
	// the important thing is we DIDN'T get PermissionDenied, meaning fingerprint passed.
	// Also verify the handler was actually called.
	if err != nil {
		st, ok := status.FromError(err)
		require.True(t, ok)
		// Should NOT be PermissionDenied (that would mean fingerprint check failed)
		assert.NotEqual(t, codes.PermissionDenied, st.Code(),
			"should not get PermissionDenied when fingerprint is in allowlist")
	}
	assert.True(t, handlerCalled, "Handler should have been called (fingerprint check passed)")
}

// TestIntegration_mTLS_InvalidClientCert tests that a client with an invalid cert
// (not signed by the server's trusted CA) is rejected at the TLS level.
func TestIntegration_mTLS_InvalidClientCert(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA for server
	caCert, caKey := generateTestCA(t)
	caCertPath := writeCertToFile(t, tmpDir, "ca.pem", caCert)

	// Generate server cert signed by CA
	serverCert, serverKey := generateTestCertSignedByCA(t, "localhost", caCert, caKey)
	serverCertPath := writeCertToFile(t, tmpDir, "server.pem", serverCert)
	serverKeyPath := writeKeyToFile(t, tmpDir, "server-key.pem", serverKey)

	// Generate a DIFFERENT CA for client (server won't trust it)
	otherCACert, otherCAKey := generateTestCA(t)
	otherCACertPath := writeCertToFile(t, tmpDir, "other-ca.pem", otherCACert)

	// Generate client cert signed by the OTHER CA (not trusted by server)
	clientCert, clientKey := generateTestCertSignedByCA(t, "client", otherCACert, otherCAKey)
	clientCertPath := writeCertToFile(t, tmpDir, "client.pem", clientCert)
	clientKeyPath := writeKeyToFile(t, tmpDir, "client-key.pem", clientKey)

	// Configure server with mTLS - only trusts caCert, not otherCACert
	serverCfg := model.GRPCServer{
		Addr: "127.0.0.1:0",
		TLS: model.GRPCTLS{
			Enabled:      true,
			CertFilePath: serverCertPath,
			KeyFilePath:  serverKeyPath,
			ClientCAPath: caCertPath, // Only trusts the first CA
			AllowedClientFingerprints: map[string]string{
				CertFingerprint(clientCert): "client", // Even if fingerprint matches, CA won't
			},
		},
	}

	serverOpts, err := NewServerOptions(serverCfg)
	require.NoError(t, err)

	// Start gRPC server
	server := grpc.NewServer(serverOpts...)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Stop()

	// Configure client - trusts the other CA for server verification
	// but presents a cert signed by otherCACert which server doesn't trust
	clientCfg := model.GRPCClientTLS{
		Addr:         listener.Addr().String(),
		TLS:          true,
		CAFilePath:   otherCACertPath, // Client trusts other CA (for server cert verification)
		CertFilePath: clientCertPath,
		KeyFilePath:  clientKeyPath,
		ServerName:   "localhost",
	}

	conn, err := NewClientConn(clientCfg)
	require.NoError(t, err)
	defer conn.Close()

	// Make an RPC call - should fail at TLS handshake level
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	err = conn.Invoke(ctx, "/test.Service/Method", nil, nil)
	require.Error(t, err)

	// The error should be related to TLS/certificate verification
	// Could be Unavailable or Unknown depending on when the handshake fails
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error, got: %v", err)
	// TLS handshake failures typically result in Unavailable
	assert.True(t, st.Code() == codes.Unavailable || st.Code() == codes.Unknown,
		"expected Unavailable or Unknown (TLS failure), got %s: %s", st.Code(), st.Message())
}
