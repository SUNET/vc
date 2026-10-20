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
	"github.com/SUNET/vc/pkg/helpers"
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
	if c.cfg.APIGW == nil {
		return nil
	}

	c.seedSources = map[string]seed.Source{}

	for name, src := range c.cfg.APIGW.Seeds {
		if src == nil {
			return fmt.Errorf("apigw.seeds.%s: empty seed source", name)
		}
		switch src.Model {
		case model.SeedModelDerived:
			secret, err := seedSecret(name, src.SecretPath, src.Secret)
			if err != nil {
				return err
			}
			deriver, err := seed.NewDeriver(secret, src.SeedBytes)
			if err != nil {
				return fmt.Errorf("apigw.seeds.%s: %w", name, err)
			}
			c.seedSources[name] = deriver
			c.log.Info("Initialized seed source", "name", name, "model", src.Model, "seed_bytes", deriver.SeedBytes())
		default:
			// "derived" is the only model. Configuration validation
			// refuses anything else first; this is the second gate, so
			// an unknown model cannot become a source that derives from
			// nothing.
			return fmt.Errorf("apigw.seeds.%s: unknown model %q", name, src.Model)
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
				return fmt.Errorf("%s: names seed source %q, which is not configured in apigw.seeds", where, claim.Seed)
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

		if err := c.checkSeedAdvertisement(scope, meta); err != nil {
			return err
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

// checkSeedAdvertisement refuses a delivering scope whose advertisement
// would be malformed, or that no wallet could ever complete.
//
// At STARTUP, and not at issuance, because neither failure can be
// caught there. SPEC 2.6 section 5A.4 allows one to eight valid
// namespace names; a wallet treats a malformed entry as if the
// configuration were not offered, so it never sends a request for
// issuance to refuse. And a scope that delivers on an issuer with no
// credential-encryption keys is a deadlock: checkResponseEncryption
// refuses a request that carries encryption parameters, because this
// issuer supports none, while deliverSeeds refuses one that omits
// them. The credential is advertised and cannot be issued either way.
func (c *Client) checkSeedAdvertisement(scope string, meta *model.CredentialMetadata) error {
	namespaces := seedNamespacesForScope(meta)
	if len(namespaces) == 0 {
		return nil
	}

	where := fmt.Sprintf("credential_metadata.%s", scope)
	if len(namespaces) > maxSeedNamespaces {
		return fmt.Errorf("%s: delivers %d seed namespaces; the advertisement carries at most %d",
			where, len(namespaces), maxSeedNamespaces)
	}
	for _, namespace := range namespaces {
		switch {
		case len(namespace) > maxSeedNamespaceBytes:
			return fmt.Errorf("%s: seed namespace %q is %d bytes; at most %d",
				where, namespace, len(namespace), maxSeedNamespaceBytes)
		case namespace == model.SeedNamespacesMember:
			return fmt.Errorf("%s: %q is reserved for the advertisement itself and cannot be a seed namespace",
				where, namespace)
		}
	}

	if c.issuerMetadata == nil || c.issuerMetadata.NotificationEndpoint == "" {
		// A delivered seed comes with a notification_id, which is how
		// a wallet reports that the commitment it was given does not
		// open with the seed it was sent (privatedata-spec SPEC 2.6
		// section 5A.2). Without an advertised notification endpoint
		// the wallet has nowhere to send it: the id is minted, the
		// feedback loop is silently absent, and a credential whose
		// commitment nobody can open is indistinguishable from one
		// that works.
		//
		// vc serves the endpoint unconditionally; it is ADVERTISED
		// only when apigw.issuer_metadata.notification_endpoint is
		// set, and a wallet that cannot see it in the metadata will
		// not use it.
		return fmt.Errorf("%s: delivers a seed, which comes with a notification_id the wallet reports a failed "+
			"commitment check through, but this issuer advertises no notification endpoint - set "+
			"apigw.issuer_metadata.notification_endpoint", where)
	}

	if c.cfg.APIGW == nil || len(c.cfg.APIGW.IssuerMetadata.CredentialEncryption.Keys) == 0 {
		return fmt.Errorf("%s: delivers a seed, which is only sent in an encrypted response, but this issuer has no "+
			"apigw.issuer_metadata.credential_encryption.keys - a wallet asking for encryption would be refused for "+
			"lack of support, and one not asking would be refused for the seed", where)
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
		return nil, fmt.Errorf("apigw.seeds.%s: set secret_path or the secret in the secrets file, not both", name)
	case path != "":
		decoded, err := helpers.ReadBase64URLFile(path)
		if err != nil {
			return nil, fmt.Errorf("apigw.seeds.%s: failed to load the derivation secret: %w", name, err)
		}
		return decoded, nil
	case inline != "":
		decoded, err := helpers.DecodeBase64URL(inline)
		if err != nil {
			return nil, fmt.Errorf("apigw.seeds.%s: failed to load the derivation secret: %w", name, err)
		}
		return decoded, nil
	default:
		// Naming the secrets FILE, because setting the same key in
		// config.yaml is the mistake this message has to pre-empt: it
		// parses, it is ignored, and the operator reads this message
		// as if they had already done what it asks.
		return nil, fmt.Errorf("apigw.seeds.%s: set secret_path, or apigw.seeds.%s.secret in the SECRETS file "+
			"(the same key in config.yaml is not read)", name, name)
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

// signingFormatJWP names the BBS/JWP signing path.
//
// Not an OpenID4VP format identifier, because there is no commitment
// configuration this path can legitimately serve: W3C formats are
// refused at startup, so a scope reaching MakeJWP with commitments
// configured is by definition signing through the wrong handler. It only
// has to be a value no commitment-capable scope can match.
const signingFormatJWP = "jwp"

// injectCommitments writes this scope's seed-backed claims into the
// document data, and returns it re-encoded.
//
// schemas are the declarations the credential is issued against, which
// the issuer receives inline per request rather than holding.
//
// A no-op for a scope with no commitments configured, which is every scope
// in a deployment that does not use the feature - including the encoding
// round trip, so nothing changes for anybody else.
func (c *Client) injectCommitments(ctx context.Context, scope string, signingFormat string, documentData []byte) ([]byte, map[string]string, error) {
	meta := c.cfg.GetCredentialMetadata(scope)
	if meta == nil || len(meta.Commitments) == 0 {
		return documentData, nil, nil
	}

	// The scope says which format its commitments were configured and
	// validated for; this handler says which one is actually being
	// signed. Everything below reads the CONFIGURED format - flat or
	// nested document data, which schema the path is checked against,
	// whether the VCTM disclosure rules apply - so a caller that signs a
	// scope through a different handler gets a commitment resolved by one
	// format's rules and signed under another's.
	//
	// The concrete loss: a MakeSDJWT request naming an mso_mdoc scope
	// skips the VCTM check that requires the commitment to be
	// disclosable, so a stable per-subject identifier ends up in the
	// clear signed payload where the holder cannot withhold it - which is
	// the one property the whole feature exists to provide.
	if !meta.CommitmentsMatchSigningFormat(signingFormat) {
		return nil, nil, fmt.Errorf("scope %q configures commitments for format %q but is being signed as %q; "+
			"the commitment would be resolved by one format's rules and signed under another's",
			scope, meta.Format, signingFormat)
	}

	// UseNumber, so that re-encoding the document does not rewrite claims
	// this function never touched. Plain Unmarshal turns every JSON number
	// into a float64, and marshalling that back changes any integer past
	// 2^53 - 9007199254740993 is signed as ...992. MakeJWP forwarded the
	// bytes untouched before this feature existed, so without this the
	// injection is a silent data change for every number in the document.
	doc, err := decodeDocumentData(documentData)
	if err != nil {
		return nil, nil, fmt.Errorf("commitment claims for scope %q: %w", scope, err)
	}

	flat := flatDocument(meta.Format)

	// One resolution, shared with the apigw's startup check, so the two
	// cannot disagree about where a commitment goes or how it is encoded.
	// It also refuses two configured paths that resolve to one element,
	// which an existing-value check made against the received document
	// cannot catch - neither has been written yet, so both pass and the
	// second write replaces the first commitment.
	targets, err := meta.ResolveCommitmentTargets(commitmentSchemas(meta, signingFormat))
	if err != nil {
		return nil, nil, fmt.Errorf("scope %q: %w", scope, err)
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
			return nil, nil, fmt.Errorf("%s: the document data already carries a value for it, which an issuer-held commitment must not accept", where)
		}

		subjectIDs, err := subjectIdentifiers(doc, target.Claim.Subjects, flat)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", where, err)
		}

		pending = append(pending, resolvedCommitment{target: target, subjectIDs: subjectIDs})
	}

	// Seeds to deliver, by namespace. Held only for the length of this
	// request: nothing here is persisted, cached, logged or traced, and
	// the map goes out of scope with the response.
	var delivered map[string]string

	for _, p := range pending {
		seedValue, err := c.writeCommitment(ctx, scope, p, doc, flat)
		if err != nil {
			return nil, nil, err
		}
		if !p.target.Claim.Deliver {
			continue
		}
		namespace := p.target.Claim.Namespace
		if namespace == "" {
			namespace = model.DefaultSeedNamespace
		}
		if delivered == nil {
			delivered = map[string]string{}
		}
		if existing, clash := delivered[namespace]; clash && existing != hex.EncodeToString(seedValue) {
			// Two claims of one scope delivering DIFFERENT seeds under
			// one namespace. The response carries one value per
			// namespace, so one of them would silently win and the
			// wallet's commitment check would fail against the other
			// credential - which reads as a bad credential rather than
			// a bad configuration.
			return nil, nil, fmt.Errorf("scope %q delivers two different seeds under namespace %q", scope, namespace)
		}
		delivered[namespace] = hex.EncodeToString(seedValue)
	}

	injected, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("commitment claims for scope %q: %w", scope, err)
	}
	return injected, delivered, nil
}

// commitmentSchemas is the type metadata a commitment target must be
// checked against for the format being signed.
//
// The apigw has both already - parsed at configuration load, and sent to
// the issuer with every request - so it can resolve targets itself.
// Previously each signing path inside the issuer passed whichever schema
// it happened to hold, which is how an mdoc-configured scope signed as
// SD-JWT ended up checked against nothing at all.
//
// A missing schema is REFUSED rather than skipped, by ResolveCommitmentTargets,
// which is where the reasons live: an mdoc signer emits the elements its
// schema declares and ignores anything else, so an undeclared commitment
// path would inject cleanly and issue a credential with no commitment in
// it; and the VCTM is what says the claim is selectively disclosable, so
// without it there is nothing to stop a stable identifier being signed in
// the clear.
func commitmentSchemas(meta *model.CredentialMetadata, signingFormat string) model.CredentialSchemas {
	if signingFormat == openid4vp.FormatMsoMdoc {
		return model.CredentialSchemas{MDoc: meta.MDDL}
	}
	if meta.CommitmentsMatchSigningFormat(openid4vp.FormatSDJWTVC) {
		return model.CredentialSchemas{VCTM: meta.VCTM}
	}
	return model.CredentialSchemas{}
}

func (c *Client) writeCommitment(ctx context.Context, scope string, p resolvedCommitment, doc map[string]any, flat bool) ([]byte, error) {
	where := fmt.Sprintf("commitment claim %q for scope %q", p.target.Path, scope)

	source, ok := c.seedSources[p.target.Claim.Seed]
	if !ok {
		// Unreachable if initSeedSources ran, which is the point of
		// checking here too: this function must not fall back to deriving
		// from nothing.
		return nil, fmt.Errorf("%s: seed source %q is not available", where, p.target.Claim.Seed)
	}

	seedValue, err := source.Seed(ctx, p.subjectIDs, p.target.Claim.Context)
	if err != nil {
		// The subject identifier is NOT in this error: it is the thing
		// that identifies the person, and this error reaches a log.
		return nil, fmt.Errorf("%s: %w", where, err)
	}

	commitment, err := seed.Commit(p.target.Claim.Commit, seedValue)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	expected, err := seed.CommitmentBytes(p.target.Claim.Commit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	if len(commitment) != expected {
		return nil, fmt.Errorf("%s: commitment is %d bytes, expected %d", where, len(commitment), expected)
	}

	var encoded string
	switch p.target.Encoding {
	case model.CommitmentEncodingHex:
		encoded = hex.EncodeToString(commitment)
	case model.CommitmentEncodingBase64:
		encoded = base64.StdEncoding.EncodeToString(commitment)
	default:
		return nil, fmt.Errorf("%s: unknown encoding %q", where, p.target.Encoding)
	}

	if err := setPath(doc, p.target.Element, encoded, flat); err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	return seedValue, nil
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
