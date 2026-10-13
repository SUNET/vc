package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// initSeedSources builds the seed sources this issuer offers and checks
// that every credential asking for one can actually be served.
//
// At startup rather than at first issuance, and fatal rather than logged:
// a deployment whose commitment configuration does not resolve would
// otherwise find out when someone is standing in front of a wallet, and
// what it would find out is that a credential was issued without the claim
// or with the wrong one. Both are worse than not starting.
func (c *Client) initSeedSources() error {
	if c.cfg.Issuer == nil {
		return nil
	}

	c.seedSources = map[string]seed.Source{}

	for name, src := range c.cfg.Issuer.Seeds {
		if src == nil {
			return fmt.Errorf("issuer.seeds.%s: empty seed source", name)
		}
		switch src.Model {
		case model.SeedModelDerived:
			secret, err := seedSecret(name, src.SecretPath, src.Secret)
			if err != nil {
				return err
			}
			deriver, err := seed.NewDeriver(secret, src.SeedBytes)
			if err != nil {
				return fmt.Errorf("issuer.seeds.%s: %w", name, err)
			}
			c.seedSources[name] = deriver
			c.log.Info("Initialized seed source", "name", name, "model", src.Model, "seed_bytes", deriver.SeedBytes())
		case model.SeedModelStored:
			// Refused rather than quietly treated as derived, which would
			// hand every subject a seed the operator did not ask for and a
			// pseudonym nobody could reproduce from the table they think
			// they have.
			return fmt.Errorf("issuer.seeds.%s: model %q needs a per-subject store, which this issuer does not have; not implemented yet",
				name, src.Model)
		default:
			return fmt.Errorf("issuer.seeds.%s: unknown model %q", name, src.Model)
		}
	}

	return c.checkCommitmentClaims()
}

// checkCommitmentClaims refuses a commitment configuration this build
// cannot honour, naming what is missing.
func (c *Client) checkCommitmentClaims() error {
	if c.cfg.Common == nil {
		return nil
	}

	for scope, meta := range c.cfg.Common.CredentialMetadata {
		if meta == nil {
			continue
		}
		for path, claim := range meta.Commitments {
			where := fmt.Sprintf("credential_metadata.%s.commitments.%s", scope, path)
			if claim == nil {
				return fmt.Errorf("%s: empty commitment", where)
			}
			if path == "" {
				return fmt.Errorf("credential_metadata.%s.commitments: a claim path is empty", scope)
			}

			if claim.Source != "" {
				// A holder-supplied commitment has to be remembered: the
				// nym_auth rulebook requires an issuer to allow only one
				// per subject, and enforcing that needs a record this
				// issuer has nowhere to keep. Accepting one without the
				// record would look like support for the configuration
				// that rule exists for, and would not be.
				return fmt.Errorf("%s: source %q needs a record of what a subject already supplied, which this issuer has no store for; not implemented yet",
					where, claim.Source)
			}

			if claim.Seed == "" {
				return fmt.Errorf("%s: no seed source named", where)
			}
			if _, ok := c.seedSources[claim.Seed]; !ok {
				return fmt.Errorf("%s: names seed source %q, which is not configured in issuer.seeds", where, claim.Seed)
			}
			if claim.Subject == "" {
				return fmt.Errorf("%s: no subject path named; a seed must be a function of some stable identifier", where)
			}
			if _, err := seed.CommitmentBytes(claim.Commit); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
			if _, err := commitmentEncoding(claim, meta.Format); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		}
	}
	return nil
}

// seedSecret resolves a derivation secret from whichever of the two ways
// it was configured.
//
// Both set, or neither, is refused rather than resolved by precedence -
// the same rule as the BBS keys, for the same reason: a deployment with
// two sources of truth cannot tell which one is live, and an operator
// editing the half that is not would see no effect at all. Here it is
// worse than for a signing key, because the wrong secret does not fail. It
// produces perfectly well-formed commitments that nothing can ever remap.
func seedSecret(name, path, inline string) ([]byte, error) {
	switch {
	case path != "" && inline != "":
		return nil, fmt.Errorf("issuer.seeds.%s: set secret_path or secret, not both", name)
	case path != "":
		decoded, err := readBase64URLFile(path)
		if err != nil {
			return nil, fmt.Errorf("issuer.seeds.%s: failed to load the derivation secret: %w", name, err)
		}
		return decoded, nil
	case inline != "":
		decoded, err := decodeBase64URL(inline)
		if err != nil {
			return nil, fmt.Errorf("issuer.seeds.%s: failed to load the derivation secret: %w", name, err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("issuer.seeds.%s: set either secret_path or secret", name)
	}
}

// injectCommitments writes this scope's seed-backed claims into the
// document data, and returns it re-encoded.
//
// A no-op for a scope with no commitments configured, which is every scope
// in a deployment that does not use the feature - including the encoding
// round trip, so nothing changes for anybody else.
func (c *Client) injectCommitments(ctx context.Context, scope string, documentData []byte) ([]byte, error) {
	meta := c.cfg.GetCredentialMetadata(scope)
	if meta == nil || len(meta.Commitments) == 0 {
		return documentData, nil
	}

	var doc map[string]any
	if err := json.Unmarshal(documentData, &doc); err != nil {
		return nil, fmt.Errorf("commitment claims for scope %q: document data is not a JSON object: %w", scope, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}

	for path, claim := range meta.Commitments {
		if err := c.injectOneCommitment(ctx, scope, path, claim, meta.Format, doc); err != nil {
			return nil, err
		}
	}

	injected, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("commitment claims for scope %q: %w", scope, err)
	}
	return injected, nil
}

func (c *Client) injectOneCommitment(ctx context.Context, scope, path string, claim *model.CommitmentClaim, format string, doc map[string]any) error {
	where := fmt.Sprintf("commitment claim %q for scope %q", path, scope)

	// An upstream value must never win. The whole property of an
	// issuer-held commitment is that the issuer holds the seed; a value
	// arriving in the document data was computed by something that does
	// not, so signing it would produce a credential that looks remappable
	// and is not. Refused rather than overwritten, because a data source
	// supplying it is a misconfiguration somebody needs to hear about.
	flat := flatDocument(format)
	if existing, present := lookupPath(doc, path, flat); present && existing != nil {
		return fmt.Errorf("%s: the document data already carries a value for it, which an issuer-held commitment must not accept", where)
	}

	source, ok := c.seedSources[claim.Seed]
	if !ok {
		// Unreachable if initSeedSources ran, which is the point of
		// checking here too: this function must not fall back to deriving
		// from nothing.
		return fmt.Errorf("%s: seed source %q is not available", where, claim.Seed)
	}

	subjectID, err := subjectIdentifier(doc, claim.Subject, flat)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}

	seedValue, err := source.Seed(ctx, subjectID, claim.Context)
	if err != nil {
		// The subject identifier is NOT in this error: it is the thing
		// that identifies the person, and this error reaches a log.
		return fmt.Errorf("%s: %w", where, err)
	}

	commitment, err := seed.Commit(claim.Commit, seedValue)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	expected, err := seed.CommitmentBytes(claim.Commit)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if len(commitment) != expected {
		return fmt.Errorf("%s: commitment is %d bytes, expected %d", where, len(commitment), expected)
	}

	encoding, err := commitmentEncoding(claim, format)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	var encoded string
	switch encoding {
	case encodingHex:
		encoded = hex.EncodeToString(commitment)
	case encodingBase64:
		encoded = base64.StdEncoding.EncodeToString(commitment)
	}

	setPath(doc, path, encoded, flat)
	return nil
}

const (
	encodingHex    = "hex"
	encodingBase64 = "base64"
)

// commitmentEncoding decides how the commitment bytes are written into the
// document data.
//
// The default is not a preference, it is what the format's carrier
// accepts: an mso_mdoc bstr element arrives as JSON, which mdoc decodes as
// standard base64, so a hex string there would be signed as the ASCII of
// the hex rather than the 32 bytes. Everything else carries the value as
// the claim itself, where hex is what the nym_auth circuits read.
func commitmentEncoding(claim *model.CommitmentClaim, format string) (string, error) {
	switch claim.Encoding {
	case encodingHex, encodingBase64:
		return claim.Encoding, nil
	case "":
		if format == openid4vp.FormatMsoMdoc {
			return encodingBase64, nil
		}
		return encodingHex, nil
	default:
		return "", fmt.Errorf("unknown encoding %q", claim.Encoding)
	}
}

// subjectIdentifier reads the stable subject identifier out of the
// document data.
//
// Absent, empty or not a string is an error and never a default. Deriving
// over "" would give every subject whose identity did not resolve the same
// seed, and so the same pseudonym - which is the exact failure the
// identifier exists to prevent, arriving silently.
func subjectIdentifier(doc map[string]any, path string, flat bool) (string, error) {
	raw, present := lookupPath(doc, path, flat)
	if !present || raw == nil {
		return "", fmt.Errorf("the subject path %q is not present in the document data", path)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("the subject path %q is %T, not a string", path, raw)
	}
	if strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("the subject path %q is empty", path)
	}
	return s, nil
}

// flatDocument reports whether this format's document data is a flat map
// keyed by the whole claim identifier.
//
// It is, for mso_mdoc: the document is keyed by element identifier and
// mdoc.addElements looks up doc[elementID] directly, and an element
// identifier may itself contain dots - a namespace-qualified one does. So
// a dotted path there is one key, not a descent. Every other format
// carries a JSON object where a dotted path means what it usually means.
func flatDocument(format string) bool { return format == openid4vp.FormatMsoMdoc }

// lookupPath resolves a claim path in the document data.
func lookupPath(doc map[string]any, path string, flat bool) (any, bool) {
	if v, ok := doc[path]; ok {
		return v, true
	}
	if flat {
		return nil, false
	}

	segments := strings.Split(path, ".")
	if len(segments) == 1 {
		return nil, false
	}

	var current any = doc
	for _, segment := range segments {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// setPath writes a value at a claim path, creating intermediate objects
// where the format has them.
//
// The shape is decided by the format and NOT by whether the key already
// exists - which is the obvious-looking rule and is wrong, because a claim
// being written for the first time never exists yet. Deciding that way
// would nest every dotted mdoc element identifier into a tree the signer
// then cannot find.
func setPath(doc map[string]any, path string, value any, flat bool) {
	segments := strings.Split(path, ".")
	if flat || len(segments) == 1 {
		doc[path] = value
		return
	}

	current := doc
	for _, segment := range segments[:len(segments)-1] {
		next, ok := current[segment].(map[string]any)
		if !ok {
			next = map[string]any{}
			current[segment] = next
		}
		current = next
	}
	current[segments[len(segments)-1]] = value
}
