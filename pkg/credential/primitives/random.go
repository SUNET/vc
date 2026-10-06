package primitives

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Random value formats. The names are the configured `format` values.
const (
	// RandomFormatUUID is a version 4 UUID in canonical textual form.
	RandomFormatUUID = "uuid"
	// RandomFormatHex is lower-case hex over RandomArgs.Bytes random bytes.
	RandomFormatHex = "hex"
	// RandomFormatBase64URL is unpadded base64url over RandomArgs.Bytes
	// random bytes.
	RandomFormatBase64URL = "base64url"
)

const (
	// defaultRandomBytes backs a hex or base64url value when none is
	// configured. 16 bytes is the entropy of a version 4 UUID's random part
	// plus the six bits it spends on version and variant, so the default is
	// not weaker than the default format.
	defaultRandomBytes = 16
	// minRandomBytes keeps a configured length from being trivially
	// guessable; maxRandomBytes keeps a claim from becoming a payload.
	minRandomBytes = 8
	maxRandomBytes = 64
)

// RandomArgs configures the random primitive.
//
// It writes a freshly generated random value to a claim the source data did
// not supply. The use case is a claim a credential requires but
// authentication cannot provide - a document identifier that has to be
// unique across issued credentials being the one this was written for
// (SUNET/vc#736).
//
// Where the value is generated decides how long it lives, because a
// derivation runs where its data source runs it:
//
//   - assertion sources (SAML, OIDC) run derivations in the ACS or callback,
//     BEFORE the document is cached, so one value is generated per
//     authentication and every credential issued from that session carries
//     it - including each credential of a batch.
//   - other sources run derivations per credential request, so each request
//     mints a new value, and a re-issuance will not match the first.
//
// For an identifier meant to name a credential dataset, the first is what is
// wanted, which is also the case the issue describes.
//
// Nothing here checks that a value has not been issued before. Uniqueness
// rests on the generator: a version 4 UUID has 122 random bits, and hex and
// base64url take theirs from crypto/rand. That is the same basis every other
// identifier in this system uses, and it is a statistical claim rather than
// an enforced one.
type RandomArgs struct {
	// Output is the target claim name. Supports dot-notation claim paths
	// (e.g. "identity.document_id") so this primitive can target the same
	// nested claims that AttributeMapper materialises.
	//
	// There is no Input: this primitive reads nothing.
	Output string `yaml:"output" validate:"required" doc_example:"document_id"`

	// Format selects the shape of the value: "uuid" (the default), "hex" or
	// "base64url".
	Format string `yaml:"format,omitempty" validate:"omitempty,oneof=uuid hex base64url" doc_example:"uuid"`

	// Bytes is how many random bytes back a "hex" or "base64url" value,
	// between 8 and 64. Ignored for "uuid", whose length the format fixes.
	// Defaults to 16.
	Bytes int `yaml:"bytes,omitempty" validate:"omitempty,min=8,max=64" doc_example:"16"`

	// Overwrite replaces a value the source data already supplied.
	//
	// False by default, and deliberately: this primitive exists to fill a
	// claim authentication could not provide, and silently replacing a real
	// identifier with a random one is a worse failure than leaving the
	// derivation with nothing to do. Set it only where the claim is meant to
	// be random every time regardless of what arrived.
	Overwrite bool `yaml:"overwrite,omitempty"`
}

// Apply implements Applier.
func (a *RandomArgs) Apply(claims map[string]any, _ time.Time) (map[string]any, error) {
	if a.Output == "" {
		return nil, fmt.Errorf("output is required")
	}

	// A dotted output whose parent is already a scalar is a configuration
	// error, and one this primitive has to catch itself. Every other
	// primitive reads an input first, so it finds nothing and does nothing;
	// this one generates regardless, and the accumulating merge in
	// ApplyDerivations would then replace that scalar with a map - losing a
	// claim the source data did supply.
	if err := checkOutputParent(claims, a.Output); err != nil {
		return nil, err
	}

	if !a.Overwrite {
		if v, present := lookupClaim(claims, a.Output); present && !isBlankClaim(v) {
			return nil, nil
		}
	}

	value, err := a.generate()
	if err != nil {
		return nil, err
	}

	out := map[string]any{}
	if err := setClaim(out, a.Output, value); err != nil {
		return nil, err
	}

	return out, nil
}

// generate produces one value in the configured format. Config validation
// has already rejected an unknown format and an out-of-range length, but
// this is reached by callers that build a Derivation programmatically too,
// so it checks rather than assumes.
func (a *RandomArgs) generate() (string, error) {
	format := a.Format
	if format == "" {
		format = RandomFormatUUID
	}

	if format == RandomFormatUUID {
		// NewRandom rather than New or NewString: those panic when the
		// system's entropy source fails, and a credential is not worth a
		// process.
		u, err := uuid.NewRandom()
		if err != nil {
			return "", fmt.Errorf("generating a uuid: %w", err)
		}
		return u.String(), nil
	}

	n := a.Bytes
	if n == 0 {
		n = defaultRandomBytes
	}
	if n < minRandomBytes || n > maxRandomBytes {
		return "", fmt.Errorf("bytes must be between %d and %d, got %d", minRandomBytes, maxRandomBytes, n)
	}

	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}

	switch format {
	case RandomFormatHex:
		return hex.EncodeToString(buf), nil
	case RandomFormatBase64URL:
		return base64.RawURLEncoding.EncodeToString(buf), nil
	default:
		return "", fmt.Errorf("unknown format %q; want one of %s, %s, %s",
			format, RandomFormatUUID, RandomFormatHex, RandomFormatBase64URL)
	}
}

// checkOutputParent refuses a dotted output path whose parents are not maps
// in the claims it is about to be merged into.
func checkOutputParent(claims map[string]any, path string) error {
	parts := strings.Split(path, ".")
	if len(parts) == 1 {
		return nil
	}

	var cur any = claims
	for i, p := range parts[:len(parts)-1] {
		m, ok := cur.(map[string]any)
		if !ok {
			return fmt.Errorf("output %q: %s is not a map", path, strings.Join(parts[:i], "."))
		}
		v, present := m[p]
		if !present {
			return nil
		}
		cur = v
	}
	if _, ok := cur.(map[string]any); !ok {
		return fmt.Errorf("output %q: %s is not a map", path, strings.Join(parts[:len(parts)-1], "."))
	}

	return nil
}

// isBlankClaim reports whether a claim carries nothing worth keeping. A
// present-but-empty claim is what an attribute mapping's `default: ""`
// leaves behind, and treating it as a value would make this primitive a
// no-op in exactly the case it was written for.
func isBlankClaim(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []string:
		return len(t) == 0
	case []any:
		return len(t) == 0
	default:
		return false
	}
}
