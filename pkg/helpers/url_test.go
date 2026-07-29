package helpers

import (
	"testing"
)

func TestHostFromURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr bool
	}{
		{
			name:   "https with host only",
			rawURL: "https://example.com",
			want:   "example.com",
		},
		{
			name:   "https with host and port",
			rawURL: "https://example.com:8443",
			want:   "example.com:8443",
		},
		{
			name:   "https with path",
			rawURL: "https://example.com/foo/bar",
			want:   "example.com",
		},
		{
			name:   "https with path and port",
			rawURL: "https://example.com:8443/foo/bar",
			want:   "example.com:8443",
		},
		{
			name:   "http scheme",
			rawURL: "http://example.com",
			want:   "example.com",
		},
		{
			name:   "http with port and path",
			rawURL: "http://localhost:8080/api/v1",
			want:   "localhost:8080",
		},
		{
			name:   "with query string",
			rawURL: "https://example.com/path?key=val",
			want:   "example.com",
		},
		{
			name:   "with fragment",
			rawURL: "https://example.com/path#section",
			want:   "example.com",
		},
		{ // #nosec G101
			name:   "with userinfo",
			rawURL: "https://user:pass@example.com/path",
			want:   "example.com",
		},
		{
			name:    "empty string",
			rawURL:  "",
			wantErr: true,
		},
		{
			name:    "no scheme produces empty host",
			rawURL:  "example.com",
			wantErr: true,
		},
		{
			name:    "bare path",
			rawURL:  "/just/a/path",
			wantErr: true,
		},
		{
			name:    "scheme only",
			rawURL:  "https://",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HostFromURL(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Errorf("HostFromURL(%q) expected error, got %q", tt.rawURL, got)
				}
				return
			}
			if err != nil {
				t.Errorf("HostFromURL(%q) unexpected error: %v", tt.rawURL, err)
				return
			}
			if got != tt.want {
				t.Errorf("HostFromURL(%q) = %q, want %q", tt.rawURL, got, tt.want)
			}
		})
	}
}
