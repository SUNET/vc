package apiv1

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/SUNET/vc/pkg/credential"
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
			if len(claim.Subjects) == 0 {
				return fmt.Errorf("%s: no subject paths named; a seed must be a function of some stable identifier", where)
			}
			for i, path := range claim.Subjects {
				if strings.TrimSpace(path) == "" {
					return fmt.Errorf("%s: subject path %d of %d is empty", where, i+1, len(claim.Subjects))
				}
			}
			if _, err := seed.CommitmentBytes(claim.Commit); err != nil {
				return fmt.Errorf("%s: %w", where, err)
			}
		}

		// Everything about WHERE and HOW - element resolution, encoding,
		// the carrier, and two paths resolving to one element - through
		// the shared resolver, so this and the apigw's startup check
		// cannot drift apart. Without a schema here it checks what it can;
		// the issuer receives schemas inline per request, so the rest is
		// checked again at issuance.
		if _, err := meta.ResolveCommitmentTargets(model.CredentialSchemas{}); err != nil {
			return fmt.Errorf("credential_metadata.%s: %w", scope, err)
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
		return nil, fmt.Errorf("issuer.seeds.%s: set secret_path or the secret in the secrets file, not both", name)
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
		return nil, fmt.Errorf("issuer.seeds.%s: set secret_path, or issuer.seeds.%s.secret in the secrets file", name, name)
	}
}

// decodeDocumentData reads the document, preserving numbers exactly and
// rejecting anything the whole input is not.
//
// UseNumber, because plain Unmarshal turns every JSON number into a
// float64 and marshalling that back changes any integer past 2^53 -
// 9007199254740993 is re-encoded as ...992. These documents are forwarded
// untouched when no commitment is configured, so without it the injection
// silently rewrites numbers it has nothing to do with.
//
// And a trailing-bytes check, because a Decoder stops at the end of the
// first JSON value: `{"a":1} garbage` decodes happily and re-marshals as
// valid JSON, which is strictly weaker than the Unmarshal this replaced.
// MakeVC20 had that validation before, and the JWP validator still
// assumes it.
func decodeDocumentData(documentData []byte) (map[string]any, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(documentData))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("document data is not a JSON object: %w", err)
	}
	// A SECOND decode, required to hit io.EOF - not a look at
	// decoder.Buffered(), which only exposes what the decoder happened to
	// prefetch. With enough whitespace between the object and the garbage
	// the prefetch holds nothing but whitespace, and the check passes on
	// an input it was written to reject.
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("document data carries trailing content after the JSON object")
	}
	if doc == nil {
		doc = map[string]any{}
	}
	return doc, nil
}

// resolvedCommitment is one commitment claim with everything the write
// pass needs already settled: nothing below reads configuration or the
// document again, which is what makes the pass order-independent.
type resolvedCommitment struct {
	target     model.CommitmentTarget
	subjectIDs []string
}

// injectCommitments writes this scope's seed-backed claims into the
// document data, and returns it re-encoded.
//
// schemas are the declarations the credential is issued against, which
// the issuer receives inline per request rather than holding.
//
// A no-op for a scope with no commitments configured, which is every scope
// in a deployment that does not use the feature - including the encoding
// round trip, so nothing changes for anybody else.
func (c *Client) injectCommitments(ctx context.Context, scope string, documentData []byte, schemas model.CredentialSchemas) ([]byte, error) {
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
	doc, err := decodeDocumentData(documentData)
	if err != nil {
		return nil, fmt.Errorf("commitment claims for scope %q: %w", scope, err)
	}

	flat := flatDocument(meta.Format)

	// One resolution, shared with the apigw's startup check, so the two
	// cannot disagree about where a commitment goes or how it is encoded.
	// It also refuses two configured paths that resolve to one element,
	// which an existing-value check made against the received document
	// cannot catch - neither has been written yet, so both pass and the
	// second write replaces the first commitment.
	targets, err := meta.ResolveCommitmentTargets(schemas)
	if err != nil {
		return nil, fmt.Errorf("scope %q: %w", scope, err)
	}

	// Every subject identifier is resolved from the document AS RECEIVED,
	// before anything is written to it.
	//
	// Resolving inside the write loop would let one commitment derive from
	// another's freshly injected value - a seed computed over a
	// commitment, identifying nobody, with no error anywhere. Subject is
	// documented as coming from the received document data, so it reads
	// the received document data.
	pending := make([]resolvedCommitment, 0, len(targets))
	for _, target := range targets {
		where := fmt.Sprintf("commitment claim %q for scope %q", target.Path, scope)

		// Against the RESOLVED element, which is the key the signer reads.
		// Checking the configured spelling instead would miss an upstream
		// bare value under a namespace-qualified configuration, and that
		// value is the one that would be signed.
		if existing, present := lookupPath(doc, target.Element, flat); present && existing != nil {
			return nil, fmt.Errorf("%s: the document data already carries a value for it, which an issuer-held commitment must not accept", where)
		}

		subjectIDs, err := subjectIdentifiers(doc, target.Claim.Subjects, flat)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}

		pending = append(pending, resolvedCommitment{target: target, subjectIDs: subjectIDs})
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

func (c *Client) writeCommitment(ctx context.Context, scope string, p resolvedCommitment, doc map[string]any, flat bool) error {
	where := fmt.Sprintf("commitment claim %q for scope %q", p.target.Path, scope)

	source, ok := c.seedSources[p.target.Claim.Seed]
	if !ok {
		// Unreachable if initSeedSources ran, which is the point of
		// checking here too: this function must not fall back to deriving
		// from nothing.
		return fmt.Errorf("%s: seed source %q is not available", where, p.target.Claim.Seed)
	}

	seedValue, err := source.Seed(ctx, p.subjectIDs, p.target.Claim.Context)
	if err != nil {
		// The subject identifier is NOT in this error: it is the thing
		// that identifies the person, and this error reaches a log.
		return fmt.Errorf("%s: %w", where, err)
	}

	commitment, err := seed.Commit(p.target.Claim.Commit, seedValue)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	expected, err := seed.CommitmentBytes(p.target.Claim.Commit)
	if err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if len(commitment) != expected {
		return fmt.Errorf("%s: commitment is %d bytes, expected %d", where, len(commitment), expected)
	}

	var encoded string
	switch p.target.Encoding {
	case model.CommitmentEncodingHex:
		encoded = hex.EncodeToString(commitment)
	case model.CommitmentEncodingBase64:
		encoded = base64.StdEncoding.EncodeToString(commitment)
	default:
		return fmt.Errorf("%s: unknown encoding %q", where, p.target.Encoding)
	}

	if err := setPath(doc, p.target.Element, encoded, flat); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	return nil
}

// subjectIdentifier reads the stable subject identifier out of the
// document data.
//
// Absent, empty or not a string is an error and never a default. Deriving
// over "" would give every subject whose identity did not resolve the same
// seed, and so the same pseudonym - which is the exact failure the
// identifier exists to prevent, arriving silently.
// subjectIdentifiers resolves the configured paths IN ORDER.
//
// Every path must resolve to a non-empty string, and a failure refuses
// the issuance rather than deriving over what did resolve. Skipping an
// absent entry would be the dangerous repair: ["a",""] would then derive
// what ["a"] derives, so a subject missing one identifier would be handed
// the seed - and the pseudonym - of a different subject.
func subjectIdentifiers(doc map[string]any, paths []string, flat bool) ([]string, error) {
	if len(paths) == 0 {
		// Unreachable past startup validation, which is why it is here:
		// an empty list would otherwise derive from nothing at all.
		return nil, errors.New("no subject paths are configured")
	}
	out := make([]string, 0, len(paths))
	for i, path := range paths {
		id, err := subjectIdentifier(doc, path, flat)
		if err != nil {
			return nil, fmt.Errorf("subject %d of %d: %w", i+1, len(paths), err)
		}
		out = append(out, id)
	}
	return out, nil
}

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
