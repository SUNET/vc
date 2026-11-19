package main

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
	"strings"
	"testing"
	"time"
)

func testCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCheckFresh(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		next    string
		wantErr bool
	}{
		{"future", "2026-12-01T00:00:00Z", false},
		{"expired", "2026-11-01T00:00:00Z", true},
		{"exactly now", "2026-11-19T12:00:00Z", true},
		{"empty", "", true},
		{"garbage", "tomorrow", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkFresh(tt.next, now); (err != nil) != tt.wantErr {
				t.Fatalf("checkFresh(%q) error = %v, wantErr %v", tt.next, err, tt.wantErr)
			}
		})
	}
}

func TestReadCerts(t *testing.T) {
	good := testCertPEM(t)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})
	truncated := good[:len(good)-40]

	tests := []struct {
		name    string
		data    []byte
		want    int
		wantErr string
	}{
		{"one cert", good, 1, ""},
		{"comments around cert", append(append([]byte("# note\n"), good...), []byte("\n# end\n")...), 1, ""},
		{"non-certificate block", append(append([]byte{}, good...), key...), 0, "unexpected PEM block"},
		{"truncated trailing block", append(append([]byte{}, good...), truncated...), 0, "malformed or truncated"},
		{"no certificates", []byte("nothing here\n"), 0, "no certificates found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "anchors.pem")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			certs, err := readCerts(path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("readCerts error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || len(certs) != tt.want {
				t.Fatalf("readCerts = %d certs, err %v; want %d", len(certs), err, tt.want)
			}
		})
	}
}
