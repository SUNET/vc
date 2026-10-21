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

// A wallet builds htu from the URL it requested and an operator writes the
// endpoint in configuration. RFC 9449 §4.3 says to compare the two after
// URI normalization precisely because the two spellings legitimately
// differ; a byte comparison refuses correct proofs over differences RFC
// 3986 §6.2.2 defines as insignificant, and the wallet has no way to find
// out which spelling this deployment wrote down.
func TestSameHTU(t *testing.T) {
	const endpoint = "https://issuer.example.com/token"

	for _, tc := range []struct {
		name string
		htu  string
		want bool
	}{
		{name: "identical", htu: "https://issuer.example.com/token", want: true},
		{name: "an uppercase host", htu: "https://Issuer.Example.COM/token", want: true},
		{name: "an uppercase scheme", htu: "HTTPS://issuer.example.com/token", want: true},
		{name: "an explicit default port", htu: "https://issuer.example.com:443/token", want: true},
		{name: "a Unicode host against its A-label", htu: "https://xn--mnchen-3ya.example/token", want: false},

		// The path is where two endpoints on one host differ, so nothing
		// about it is normalized away.
		{name: "another endpoint on the same host", htu: "https://issuer.example.com/authorize-challenge", want: false},
		{name: "a different case in the path", htu: "https://issuer.example.com/Token", want: false},
		{name: "a different host", htu: "https://attacker.example.com/token", want: false},
		{name: "a different scheme", htu: "http://issuer.example.com/token", want: false},
		{name: "a non-default port", htu: "https://issuer.example.com:8443/token", want: false},

		// A port is a number. Leading zeroes are not part of it, so these
		// name the same endpoint as the one with no port at all - and a
		// proof refused over them is one the wallet cannot correct,
		// because the spelling is this deployment's, not the wallet's.
		{name: "the default port with a leading zero", htu: "https://issuer.example.com:0443/token", want: true},
		{name: "the default port with several", htu: "https://issuer.example.com:000443/token", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SameHTU(tc.htu, endpoint))
		})
	}

	t.Run("a Unicode host matches its A-label", func(t *testing.T) {
		assert.True(t, SameHTU("https://münchen.example/token", "https://xn--mnchen-3ya.example/token"))
	})

	// Unicode lowercasing is not the IDNA mapping: İ lowercases to i but
	// maps to xn--i-9bb, so the host must reach IDNA as written.
	t.Run("IDNA maps the host as written, not its Unicode lowercase", func(t *testing.T) {
		assert.True(t, SameHTU("https://İ.example/token", "https://xn--i-9bb.example/token"))
		assert.True(t, SameHTU("https://xn--i-9bb.example/token", "https://İ.example/token"))
		assert.False(t, SameHTU("https://İ.example/token", "https://i.example/token"))
		assert.False(t, SameHTU("https://i.example/token", "https://İ.example/token"))
	})

	// A resolver IDNA profile rejects "_", and the old lowercase fallback
	// then turned İ.my_host.example into i.my_host.example.
	t.Run("a host with an underscore is mapped, not lowercased", func(t *testing.T) {
		assert.True(t, SameHTU("https://İ.my_host.example/token", "https://xn--i-9bb.my_host.example/token"))
		assert.True(t, SameHTU("https://xn--i-9bb.my_host.example/token", "https://İ.my_host.example/token"))
		assert.True(t, SameHTU("https://MY_HOST.Example/token", "https://my_host.example/token"))
		assert.False(t, SameHTU("https://İ.my_host.example/token", "https://i.my_host.example/token"))
		assert.False(t, SameHTU("https://i.my_host.example/token", "https://İ.my_host.example/token"))
	})

	t.Run("a host IDNA rejects is compared as written", func(t *testing.T) {
		assert.False(t, SameHTU("https://A\u200dB.example/token", "https://a\u200db.example/token"))
		assert.True(t, SameHTU("https://a\u200db.example/token", "https://a\u200db.example/token"))
	})

	t.Run("a non-default port with a leading zero is the same port", func(t *testing.T) {
		assert.True(t, SameHTU("https://issuer.example.com:08443/token", "https://issuer.example.com:8443/token"))
		assert.False(t, SameHTU("https://issuer.example.com:08443/token", "https://issuer.example.com/token"))
	})

	t.Run("an empty path is the root path", func(t *testing.T) {
		assert.True(t, SameHTU("https://issuer.example.com", "https://issuer.example.com/"))
	})

	t.Run("something unparseable is compared as written", func(t *testing.T) {
		assert.False(t, SameHTU("not a uri", endpoint))
		assert.True(t, SameHTU("not a uri", "not a uri"))
	})
}

// IPv6 has many spellings of one address, and the htu comparison has to
// see through them: a wallet that compressed the endpoint URL it was given
// was answered with invalid_dpop_proof for a proof naming this very
// endpoint, and nothing on its side could fix that.
//
// The negative cases are the point of the positive ones - a canonicaliser
// that collapsed everything would pass the first half alone.
func TestSameHTU_IPv6(t *testing.T) {
	const endpoint = "https://[2001:db8::1]/token"

	for _, tc := range []struct {
		name string
		htu  string
		want bool
	}{
		{name: "identical", htu: "https://[2001:db8::1]/token", want: true},
		{name: "fully expanded", htu: "https://[2001:0db8:0:0:0:0:0:1]/token", want: true},
		{name: "expanded with every group padded", htu: "https://[2001:0db8:0000:0000:0000:0000:0000:0001]/token", want: true},
		{name: "upper case hextets", htu: "https://[2001:DB8::1]/token", want: true},
		{name: "a partially compressed form", htu: "https://[2001:db8:0:0::1]/token", want: true},
		{name: "with the default port written out", htu: "https://[2001:db8::1]:443/token", want: true},

		{name: "a different address", htu: "https://[2001:db8::2]/token", want: false},
		{name: "an address that merely looks similar", htu: "https://[2001:db80::1]/token", want: false},
		{name: "a different path on the same address", htu: "https://[2001:db8::1]/authorize-challenge", want: false},
		{name: "a non-default port", htu: "https://[2001:db8::1]:8443/token", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SameHTU(tc.htu, endpoint); got != tc.want {
				t.Fatalf("SameHTU(%q, %q) = %v, want %v", tc.htu, endpoint, got, tc.want)
			}
		})
	}

	// An IPv4-mapped literal and the dotted quad are ONE ADDRESS and TWO
	// AUTHORITIES, and htu binds the authority. The two reach a server
	// with different Host headers and can select different virtual hosts,
	// so merging them would weaken the binding this comparison exists to
	// make. net.IP.String would have merged them, by unmapping; netip
	// preserves the family, which is why it is used.
	if SameHTU("https://[::ffff:127.0.0.1]/token", "https://127.0.0.1/token") {
		t.Fatal("an IPv4-mapped IPv6 literal is a different authority from the dotted quad")
	}
	if SameHTU("https://[::ffff:127.0.0.1]/token", "https://127.0.0.2/token") {
		t.Fatal("different addresses must stay different however they are spelled")
	}

	// Equivalent spellings of the mapped literal itself still agree: the
	// refusal above is about the family, not about giving up on IPv6.
	for _, pair := range [][2]string{
		{"https://[::ffff:127.0.0.1]/token", "https://[::FFFF:127.0.0.1]/token"},
		{"https://[::ffff:127.0.0.1]/token", "https://[0:0:0:0:0:ffff:127.0.0.1]/token"},
		{"https://[::ffff:127.0.0.1]/token", "https://[::ffff:7f00:1]/token"},
	} {
		if !SameHTU(pair[0], pair[1]) {
			t.Fatalf("%q and %q are the same authority", pair[0], pair[1])
		}
	}
}

// RFC 3986 §6.2.2 makes /%74oken and /token one path, and the hex case of
// an escape insignificant. A wallet that normalized the endpoint URL it
// was configured with was refused for naming it that way.
//
// The refusals matter more than the acceptances here: this is the
// comparison that keeps a proof for /token from satisfying a request to
// another endpoint, so only the spellings the RFC calls equal may merge.
func TestSameHTU_PercentEncoding(t *testing.T) {
	for _, tc := range []struct {
		name, htu, endpoint string
		want                bool
	}{
		{
			name: "an escaped unreserved character is the character",
			htu:  "https://issuer.example.com/%74oken", endpoint: "https://issuer.example.com/token", want: true,
		},
		{
			name: "lower-case hex in an escape",
			htu:  "https://issuer.example.com/a%2fb", endpoint: "https://issuer.example.com/a%2Fb", want: true,
		},
		{
			name: "every unreserved class: letters, digits, - . _ ~",
			htu:  "https://issuer.example.com/%61%31%2D%2E%5F%7E", endpoint: "https://issuer.example.com/a1-._~", want: true,
		},
		{
			name: "both sides escaped differently",
			htu:  "https://issuer.example.com/%74%6Fken", endpoint: "https://issuer.example.com/to%6ben", want: true,
		},

		{
			name: "a reserved escape is NOT a separator",
			htu:  "https://issuer.example.com/a%2Fb", endpoint: "https://issuer.example.com/a/b", want: false,
		},
		{
			name: "an escaped space is not nothing",
			htu:  "https://issuer.example.com/to%20ken", endpoint: "https://issuer.example.com/token", want: false,
		},
		{
			name: "case still matters once decoded",
			htu:  "https://issuer.example.com/%54oken", endpoint: "https://issuer.example.com/token", want: false,
		},
		{
			name: "dot segments are not removed",
			htu:  "https://issuer.example.com/a/%2E%2E/token", endpoint: "https://issuer.example.com/token", want: false,
		},
		{
			name: "a trailing stray percent is left as written",
			htu:  "https://issuer.example.com/token%", endpoint: "https://issuer.example.com/token", want: false,
		},
		{
			name: "a non-hex escape is left as written",
			htu:  "https://issuer.example.com/to%zzken", endpoint: "https://issuer.example.com/token", want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SameHTU(tc.htu, tc.endpoint); got != tc.want {
				t.Fatalf("SameHTU(%q, %q) = %v, want %v", tc.htu, tc.endpoint, got, tc.want)
			}
			// The comparison has to be symmetric: which side a deployment
			// writes and which a wallet sends is not fixed.
			if got := SameHTU(tc.endpoint, tc.htu); got != tc.want {
				t.Fatalf("reversed: SameHTU(%q, %q) = %v, want %v", tc.endpoint, tc.htu, got, tc.want)
			}
		})
	}
}

// IDNA does the case mapping itself, and Go's ToLower disagrees with it.
//
// Folding before the mapping turned "İ.example" (U+0130) into
// "i.example", while UTS #46 maps the original to "xn--i-9bb.example" -
// so a wallet's correctly canonicalised proof was REFUSED and one naming
// the distinct authority "i.example" was ACCEPTED. Both directions are
// asserted, because the accepting one is the security half.
func TestSameHTU_UnicodeCaseIsIDNAsToDo(t *testing.T) {
	const dotted = "https://İ.example/token"         // İ.example
	const aLabel = "https://xn--i-9bb.example/token" // what UTS #46 maps it to
	const plainI = "https://i.example/token"         // what ToLower makes of it

	if !SameHTU(dotted, aLabel) {
		t.Fatalf("%q is the A-label of %q; a proof naming either must satisfy the other", aLabel, dotted)
	}
	if SameHTU(dotted, plainI) {
		t.Fatalf("%q and %q are different authorities", dotted, plainI)
	}
	if SameHTU(aLabel, plainI) {
		t.Fatalf("%q and %q are different authorities", aLabel, plainI)
	}

	// The ordinary foldings still fold - the fix is about which component
	// does the folding, not about giving it up.
	for _, pair := range [][2]string{
		{"https://MÜNCHEN.example/token", "https://xn--mnchen-3ya.example/token"},
		{"https://München.example/token", "https://münchen.example/token"},
		{"https://EXAMPLE.COM/token", "https://example.com/token"},
		{"https://ẞ.example/token", "https://ß.example/token"}, // ẞ and ß
	} {
		if !SameHTU(pair[0], pair[1]) {
			t.Fatalf("%q and %q are the same host", pair[0], pair[1])
		}
	}
}

// A wallet's browser-normalised hostname has to match the endpoint a
// deployment configured, underscores and all.
//
// idna.Lookup turns on StrictDomainName, which rejects an underscore
// anywhere in the name - so "İ.my_host.example" did not map, fell through
// to the ASCII fold, and a wallet sending the correct A-label
// "xn--i-9bb.my_host.example" was answered with invalid_dpop_proof. The
// comparison now uses the same browser profile CanonicalOrigin does.
//
// The negatives are the other half: mapping these hosts rather than
// refusing them is what keeps "İ…" and "i…" distinct, instead of leaving
// them to a Unicode fold that merges them.
func TestSameHTU_UnderscoreHostsMapLikeABrowser(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://\u0130.my_host.example/token", "https://xn--i-9bb.my_host.example/token"},
		{"https://\u0130_host.example/token", "https://xn--i_host-pyd.example/token"},
		{"https://M\u00dcNCHEN.my_host.example/token", "https://xn--mnchen-3ya.my_host.example/token"},
		{"https://MY_HOST.EXAMPLE/token", "https://my_host.example/token"},
		{"https://My_Host.Example/token", "https://my_host.example/token"},
	} {
		if !SameHTU(pair[0], pair[1]) {
			t.Fatalf("%q and %q are the same authority", pair[0], pair[1])
		}
	}

	// Still distinct, which is what the mapping buys: "İ" is not "i".
	for _, pair := range [][2]string{
		{"https://\u0130.my_host.example/token", "https://i.my_host.example/token"},
		{"https://\u0130_host.example/token", "https://i_host.example/token"},
		{"https://xn--i-9bb.my_host.example/token", "https://i.my_host.example/token"},
	} {
		if SameHTU(pair[0], pair[1]) {
			t.Fatalf("%q and %q are different authorities", pair[0], pair[1])
		}
	}
}
