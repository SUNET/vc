package apiv1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/mdoc"
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

// resolvedCommitment is one commitment claim with everything the write
// pass needs already settled: nothing below reads configuration or the
// document again, which is what makes the pass order-independent.
type resolvedCommitment struct {
	path      string // as configured, for error messages
	target    string // the key the signer actually reads
	encoding  string
	claim     *model.CommitmentClaim
	subjectID string
}

// injectCommitments writes this scope's seed-backed claims into the
// document data, and returns it re-encoded.
//
// schema is the mso_mdoc schema about to be signed, or nil for a format
// that has none.
//
// A no-op for a scope with no commitments configured, which is every scope
// in a deployment that does not use the feature - including the encoding
// round trip, so nothing changes for anybody else.
func (c *Client) injectCommitments(ctx context.Context, scope string, documentData []byte, schema *mdoc.MDDLSchema) ([]byte, error) {
	meta := c.cfg.GetCredentialMetadata(scope)
	if meta == nil || len(meta.Commitments) == 0 {
		return documentData, nil
	}

	// UseNumber, so that re-encoding the document does not rewrite claims
	// this function never touched. Plain Unmarshal turns every JSON number
	// into a float64, and marshalling that back changes any integer past
	// 2^53 - 9007199254740993 is signed as ...992. MakeJWP forwarded the
	// bytes untouched before this feature existed, so without this the
	// injection is a silent data change for every number in the document.
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(documentData))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("commitment claims for scope %q: document data is not a JSON object: %w", scope, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}

	flat := flatDocument(meta.Format)

	// Every subject identifier is resolved from the document AS RECEIVED,
	// before anything is written to it.
	//
	// Resolving inside the write loop would make the result depend on Go's
	// map iteration order: a commitment whose subject path happens to name
	// another commitment's target would sometimes find nothing and
	// sometimes find the value just injected, and the credential would
	// differ between two issuances of the same request. Subject is
	// documented as coming from the received document data, so it reads
	// the received document data.
	//
	// Sorted for the same reason - a deterministic order so that an error
	// naming one claim is the same error twice.
	pending := make([]resolvedCommitment, 0, len(meta.Commitments))
	for _, path := range slices.Sorted(maps.Keys(meta.Commitments)) {
		claim := meta.Commitments[path]
		where := fmt.Sprintf("commitment claim %q for scope %q", path, scope)
		if claim == nil {
			return nil, fmt.Errorf("%s: empty commitment", where)
		}

		// An upstream value must never win. The whole property of an
		// issuer-held commitment is that the issuer holds the seed; a
		// value arriving in the document data was computed by something
		// that does not, so signing it would produce a credential that
		// looks remappable and is not. Refused rather than overwritten,
		// because a data source supplying it is a misconfiguration
		// somebody needs to hear about.

		target, err := resolveMdocTarget(schema, path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}

		encoding, err := commitmentEncoding(claim, meta.Format)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		if err := checkMdocCarrier(schema, target, encoding); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}

		subjectID, err := subjectIdentifier(doc, claim.Subject, flat)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		// Against the RESOLVED target, which is the key the signer reads.
		// Checking the configured spelling instead would miss an upstream
		// bare value under a namespace-qualified configuration, and that
		// value is the one that would be signed.
		if existing, present := lookupPath(doc, target, flat); present && existing != nil {
			return nil, fmt.Errorf("%s: the document data already carries a value for it, which an issuer-held commitment must not accept", where)
		}

		pending = append(pending, resolvedCommitment{path: path, target: target, encoding: encoding, claim: claim, subjectID: subjectID})
	}

	for _, p := range pending {
		if err := c.writeCommitment(ctx, scope, p, doc, flat); err != nil {
			return nil, err
		}
	}

	injected, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("commitment claims for scope %q: %w", scope, err)
	}
	return injected, nil
}

// resolveMdocTarget maps a configured claim path to the key an mdoc
// document is actually keyed by, and refuses one the schema does not
// declare.
//
// Two things make this more than a lookup:
//
// An mdoc document is FLAT and keyed by bare element identifier -
// addElements reads doc[elementID] - so a namespace-qualified target
// cannot be written verbatim. Doing that drops the value AND, worse, makes
// the pre-existing-value check look at the wrong key, so an upstream bare
// "ssc" goes unnoticed and is what gets signed. The qualified spelling is
// how the claim is named everywhere else in the configuration, so it is
// accepted and NORMALISED here rather than refused.
//
// And the signer emits only the elements the schema declares, ignoring
// anything else in the document - so an undeclared target would inject
// cleanly and issue a credential with no commitment in it.
//
// An empty schema name means a format with no schema to check against,
// where the claim is the document's own and is carried as written.
func resolveMdocTarget(schema *mdoc.MDDLSchema, path string) (string, error) {
	if schema == nil {
		return path, nil
	}
	for namespace, elements := range schema.Claims {
		if _, ok := elements[path]; ok {
			return path, nil
		}
		if bare := strings.TrimPrefix(path, namespace+"."); bare != path {
			if _, ok := elements[bare]; ok {
				return bare, nil
			}
		}
	}
	return "", fmt.Errorf("the schema for doctype %q declares no such element, so the signer would drop it and issue a credential without the commitment", schema.DocType)
}

// checkMdocCarrier refuses an encoding the target element cannot carry.
//
// A bstr element arrives as JSON and mdoc decodes it as STANDARD BASE64.
// A 64-character SHA-256 hex string is itself valid base64, so configuring
// encoding: hex against a bstr target does not fail - it decodes to 48
// bytes of nothing and signs those as the commitment. Nothing downstream
// can tell, because a 48-byte bstr is a perfectly well-formed element.
func checkMdocCarrier(schema *mdoc.MDDLSchema, element, encoding string) error {
	if schema == nil {
		return nil
	}
	for _, elements := range schema.Claims {
		meta, ok := elements[element]
		if !ok {
			continue
		}
		if meta.ValueType == "bstr" && encoding != encodingBase64 {
			return fmt.Errorf("the schema declares it as bstr, which mdoc decodes as base64, so encoding %q would sign the decoded %[1]s string instead of the commitment", encoding)
		}
		return nil
	}
	return nil
}

func (c *Client) writeCommitment(ctx context.Context, scope string, p resolvedCommitment, doc map[string]any, flat bool) error {
	where := fmt.Sprintf("commitment claim %q for scope %q", p.path, scope)

	source, ok := c.seedSources[p.claim.Seed]
	if !ok {
		// Unreachable if initSeedSources ran, which is the point of
		// checking here too: this function must not fall back to deriving
		// from nothing.
		return fmt.Errorf("%s: seed source %q is not available", where, p.claim.Seed)
	}

	seedValue, err := source.Seed(ctx, p.subjectID, p.claim.Context)
	if err != nil {
		// The subject identifier is NOT in this error: it is the thing
		// that identifies the person, and this error reaches a log.
		return fmt.Errorf("%s: %w", where, err)
	}

	commitment, err := seed.Commit(p.claim.Commit, seedValue)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	expected, err := seed.CommitmentBytes(p.claim.Commit)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if len(commitment) != expected {
		return fmt.Errorf("%s: commitment is %d bytes, expected %d", where, len(commitment), expected)
	}

	var encoded string
	switch p.encoding {
	case encodingHex:
		encoded = hex.EncodeToString(commitment)
	case encodingBase64:
		encoded = base64.StdEncoding.EncodeToString(commitment)
	default:
		return fmt.Errorf("%s: unknown encoding %q", where, p.encoding)
	}

	if err := setPath(doc, p.target, encoded, flat); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
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
//
// Flat and nested are exclusive, not ordered. Trying the literal key
// first and falling back to a descent reads like a harmless convenience
// and is not: in a nested document a literal "identity.id" key would
// shadow the documented {"identity":{"id":...}}, and the two can carry
// different values - so a seed could be derived from the wrong subject,
// or a commitment that is not there could look pre-existing.
func lookupPath(doc map[string]any, path string, flat bool) (any, bool) {
	if flat {
		v, ok := doc[path]
		return v, ok
	}

	// A single segment traverses to exactly the same key, so there is no
	// special case for it.
	var current any = doc
	for _, segment := range strings.Split(path, ".") {
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
//
// The nested case delegates to credential.SetNestedValue, which refuses a
// path whose intermediate segment is already a scalar. Creating the map
// anyway - which is what a plain type assertion does - would DELETE that
// claim from the document on the way to signing it, and the credential
// would be issued missing an attribute nobody asked to remove.
func setPath(doc map[string]any, path string, value any, flat bool) error {
	if flat {
		doc[path] = value
		return nil
	}
	return credential.SetNestedValue(doc, path, value)
}
