package sdjwtvc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchVCTM(t *testing.T) {
	name := "given_name"
	email := "email"
	validVCTM := &VCTM{
		VCT:  "https://example.com/cred/v1",
		Name: "Test Credential",
		Claims: []Claim{
			{Path: []*string{&name}, SD: "always"},
		},
	}

	// Pre-compute VCTM-A and VCTM-B for the tampered body test.
	vctmA := &VCTM{
		VCT:  "https://example.com/cred/v1",
		Name: "Credential A",
		Claims: []Claim{
			{Path: []*string{&name}, SD: "always"},
		},
	}
	rawA, err := json.Marshal(vctmA)
	require.NoError(t, err)
	integrityA, err := vctmA.SRIIntegrity(rawA)
	require.NoError(t, err)

	vctmB := &VCTM{
		VCT:  "https://example.com/cred/v1",
		Name: "Credential B",
		Claims: []Claim{
			{Path: []*string{&name}, SD: "always"},
			{Path: []*string{&email}, SD: "always"},
		},
	}
	rawB, err := json.Marshal(vctmB)
	require.NoError(t, err)
	integrityB, err := vctmB.SRIIntegrity(rawB)
	require.NoError(t, err)
	require.NotEqual(t, integrityA, integrityB)

	tts := []struct {
		name string
		// setup returns the URL to fetch and the integrity to pass.
		setup       func(t *testing.T) (url string, integrity string)
		wantErr     bool
		errContains string
		// validate is called on success (wantErr == false).
		validate func(t *testing.T, got *VCTM)
	}{
		{
			name: "valid_integrity",
			setup: func(t *testing.T) (string, string) {
				return serveVCTM(t, validVCTM)
			},
			validate: func(t *testing.T, got *VCTM) {
				assert.Equal(t, validVCTM.VCT, got.VCT)
				assert.Equal(t, validVCTM.Name, got.Name)
				assert.Len(t, got.Claims, 1)
			},
		},
		{
			name: "missing_integrity",
			setup: func(t *testing.T) (string, string) {
				url, _ := serveVCTM(t, validVCTM)
				return url, ""
			},
			wantErr:     true,
			errContains: "integrity is required",
		},
		{
			name: "wrong_integrity",
			setup: func(t *testing.T) (string, string) {
				url, _ := serveVCTM(t, validVCTM)
				return url, "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			},
			wantErr:     true,
			errContains: "VCTM integrity mismatch",
		},
		{
			name: "server_returns_404",
			setup: func(t *testing.T) (string, string) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
				t.Cleanup(ts.Close)
				return ts.URL, "sha256-xxx"
			},
			wantErr:     true,
			errContains: "unexpected status 404",
		},
		{
			name: "invalid_json",
			setup: func(t *testing.T) (string, string) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Write([]byte(`{not json`))
				}))
				t.Cleanup(ts.Close)
				return ts.URL, "sha256-xxx"
			},
			wantErr:     true,
			errContains: "failed to parse VCTM",
		},
		{
			name: "unreachable_server",
			setup: func(t *testing.T) (string, string) {
				return "http://127.0.0.1:1", "sha256-xxx"
			},
			wantErr:     true,
			errContains: "failed to fetch VCTM",
		},
		{
			name: "tampered_body",
			setup: func(t *testing.T) (string, string) {
				// Serve VCTM-B but pass VCTM-A's integrity.
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Write(rawB)
				}))
				t.Cleanup(ts.Close)
				return ts.URL, integrityA
			},
			wantErr:     true,
			errContains: "VCTM integrity mismatch",
		},
	}

	client := New()
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			url, integrity := tt.setup(t)
			got, err := client.fetchVCTM(t.Context(), url, integrity)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, got)
			}
		})
	}
}
