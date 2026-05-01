package oauth2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDPoP_ValidateJTI(t *testing.T) {
	tests := []struct {
		name    string
		jti     string
		wantErr error
	}{
		{
			name:    "valid JTI with 16 chars",
			jti:     "84bb3266ccd6abf8",
			wantErr: nil,
		},
		{
			name:    "valid JTI with UUID",
			jti:     "550e8400-e29b-41d4-a716-446655440000",
			wantErr: nil,
		},
		{
			name:    "valid JTI with 12 chars (minimum)",
			jti:     "123456789012",
			wantErr: nil,
		},
		{
			name:    "invalid JTI too short",
			jti:     "short",
			wantErr: ErrInvalidJTI,
		},
		{
			name:    "empty JTI",
			jti:     "",
			wantErr: ErrMissingJTI,
		},
		{
			name:    "JTI with 11 chars (just under minimum)",
			jti:     "12345678901",
			wantErr: ErrInvalidJTI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dpop := &DPoP{
				JTI: tt.jti,
				HTM: "POST",
				HTU: "https://example.com",
			}
			err := dpop.ValidateJTI()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDPoP_ValidateHTM(t *testing.T) {
	tests := []struct {
		name    string
		htm     string
		wantErr error
	}{
		{
			name:    "valid POST",
			htm:     "POST",
			wantErr: nil,
		},
		{
			name:    "valid GET",
			htm:     "GET",
			wantErr: nil,
		},
		{
			name:    "valid PUT",
			htm:     "PUT",
			wantErr: nil,
		},
		{
			name:    "valid DELETE",
			htm:     "DELETE",
			wantErr: nil,
		},
		{
			name:    "valid PATCH",
			htm:     "PATCH",
			wantErr: nil,
		},
		{
			name:    "valid HEAD",
			htm:     "HEAD",
			wantErr: nil,
		},
		{
			name:    "valid OPTIONS",
			htm:     "OPTIONS",
			wantErr: nil,
		},
		{
			name:    "invalid lowercase post",
			htm:     "post",
			wantErr: ErrInvalidHTM,
		},
		{
			name:    "invalid method INVALID",
			htm:     "INVALID",
			wantErr: ErrInvalidHTM,
		},
		{
			name:    "empty HTM",
			htm:     "",
			wantErr: ErrMissingHTM,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dpop := &DPoP{
				JTI: "valid-jti-12345",
				HTM: tt.htm,
				HTU: "https://example.com",
			}
			err := dpop.ValidateHTM()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDPoP_ValidateHTU(t *testing.T) {
	tests := []struct {
		name    string
		htu     string
		wantErr error
	}{
		{
			name:    "valid HTTPS URL",
			htu:     "https://example.com/token",
			wantErr: nil,
		},
		{
			name:    "valid HTTP URL",
			htu:     "http://localhost:8080/api",
			wantErr: nil,
		},
		{
			name:    "empty HTU",
			htu:     "",
			wantErr: ErrMissingHTU,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dpop := &DPoP{
				JTI: "valid-jti-12345",
				HTM: "POST",
				HTU: tt.htu,
				IAT: time.Now().Unix(),
			}
			err := dpop.ValidateHTU()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDPoP_ValidateIAT(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		iat     int64
		wantErr error
	}{
		{
			name:    "valid current timestamp",
			iat:     now.Unix(),
			wantErr: nil,
		},
		{
			name:    "valid recent timestamp (30s ago)",
			iat:     now.Add(-30 * time.Second).Unix(),
			wantErr: nil,
		},
		{
			name:    "valid within clock skew",
			iat:     now.Add(3 * time.Second).Unix(),
			wantErr: nil,
		},
		{
			name:    "missing IAT (zero)",
			iat:     0,
			wantErr: ErrMissingIAT,
		},
		{
			name:    "negative IAT",
			iat:     -1,
			wantErr: ErrInvalidIAT,
		},
		{
			name:    "token too old (beyond maxAge)",
			iat:     now.Add(-120 * time.Second).Unix(),
			wantErr: ErrTokenTooOld,
		},
		{
			name:    "token from future (beyond clock skew)",
			iat:     now.Add(10 * time.Second).Unix(),
			wantErr: ErrTokenFromFuture,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dpop := &DPoP{
				JTI: "valid-jti-12345",
				HTM: "POST",
				HTU: "https://example.com",
				IAT: tt.iat,
			}
			err := dpop.ValidateIAT()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDPoP_ValidateIATWithWindow(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		iat       int64
		maxAge    time.Duration
		clockSkew time.Duration
		wantErr   error
	}{
		{
			name:      "custom maxAge - within window",
			iat:       now.Add(-90 * time.Second).Unix(),
			maxAge:    120 * time.Second,
			clockSkew: 5 * time.Second,
			wantErr:   nil,
		},
		{
			name:      "custom maxAge - exceeded",
			iat:       now.Add(-150 * time.Second).Unix(),
			maxAge:    120 * time.Second,
			clockSkew: 5 * time.Second,
			wantErr:   ErrTokenTooOld,
		},
		{
			name:      "custom clock skew - within tolerance",
			iat:       now.Add(15 * time.Second).Unix(),
			maxAge:    60 * time.Second,
			clockSkew: 20 * time.Second,
			wantErr:   nil,
		},
		{
			name:      "custom clock skew - exceeded",
			iat:       now.Add(15 * time.Second).Unix(),
			maxAge:    60 * time.Second,
			clockSkew: 10 * time.Second,
			wantErr:   ErrTokenFromFuture,
		},
		{
			name:      "very strict maxAge (1 second)",
			iat:       now.Add(-2 * time.Second).Unix(),
			maxAge:    1 * time.Second,
			clockSkew: 5 * time.Second,
			wantErr:   ErrTokenTooOld,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dpop := &DPoP{
				JTI: "valid-jti-12345",
				HTM: "POST",
				HTU: "https://example.com",
				IAT: tt.iat,
			}
			err := dpop.ValidateIATWithWindow(tt.maxAge, tt.clockSkew)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDPoP_Validate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		dpop    *DPoP
		wantErr error
	}{
		{
			name: "all valid fields including IAT",
			dpop: &DPoP{
				JTI: "84bb3266ccd6abf8",
				HTM: "POST",
				HTU: "https://example.com/token",
				IAT: now.Unix(),
			},
			wantErr: nil,
		},
		{
			name: "invalid JTI",
			dpop: &DPoP{
				JTI: "short",
				HTM: "POST",
				HTU: "https://example.com/token",
				IAT: now.Unix(),
			},
			wantErr: ErrInvalidJTI,
		},
		{
			name: "invalid HTM",
			dpop: &DPoP{
				JTI: "84bb3266ccd6abf8",
				HTM: "INVALID",
				HTU: "https://example.com/token",
				IAT: now.Unix(),
			},
			wantErr: ErrInvalidHTM,
		},
		{
			name: "missing HTU",
			dpop: &DPoP{
				JTI: "84bb3266ccd6abf8",
				HTM: "POST",
				HTU: "",
				IAT: now.Unix(),
			},
			wantErr: ErrMissingHTU,
		},
		{
			name: "missing IAT",
			dpop: &DPoP{
				JTI: "84bb3266ccd6abf8",
				HTM: "POST",
				HTU: "https://example.com/token",
				IAT: 0,
			},
			wantErr: ErrMissingIAT,
		},
		{
			name: "token too old",
			dpop: &DPoP{
				JTI: "84bb3266ccd6abf8",
				HTM: "POST",
				HTU: "https://example.com/token",
				IAT: now.Add(-120 * time.Second).Unix(),
			},
			wantErr: ErrTokenTooOld,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dpop.Validate()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDPoP_ValidateWithWindow(t *testing.T) {
	now := time.Now()

	dpop := &DPoP{
		JTI: "84bb3266ccd6abf8",
		HTM: "POST",
		HTU: "https://example.com/token",
		IAT: now.Add(-90 * time.Second).Unix(),
	}

	// Should fail with default window (60s maxAge)
	err := dpop.Validate()
	assert.ErrorIs(t, err, ErrTokenTooOld)

	// Should succeed with custom window (120s maxAge)
	err = dpop.ValidateWithWindow(120*time.Second, 5*time.Second)
	assert.NoError(t, err)
}
