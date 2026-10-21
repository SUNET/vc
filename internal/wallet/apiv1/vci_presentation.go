package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/internal/wallet/credential"
	"github.com/SUNET/vc/pkg/openid4vp"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// performPresentationInteraction answers an
// urn:openid:dcp:ia:openid4vp_presentation challenge and returns the
// openid4vp_response parameter to send back.
//
// The request arrives inside the 403 rather than at a request_uri, in the
// Digital Credentials API shape (signed, so it comes as a "request"
// member holding a JWT). The response goes back to the same Authorization
// Challenge Endpoint instead of to a response_uri, which is the whole of
// what ia_post.jwt means.
func (c *Client) performPresentationInteraction(ctx context.Context, challengeEndpoint string, resp *challengeResponse, vci *config.VCIScenario, result *ScenarioResult) (string, error) {
	step := StepResult{Name: "openid4vp_presentation", StartedAt: time.Now()}
	defer func() {
		step.CompletedAt = time.Now()
		result.Steps = append(result.Steps, step)
	}()

	ro, err := c.parseInteractiveAuthorizationRequest(resp.OpenID4VPRequest)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	// The audience a Key Binding JWT must carry is not the client_id it
	// would be for an ordinary Verifier: OpenID4VCI 1.1 binds it to the
	// Authorization Challenge Endpoint, prefixed, so that a presentation
	// made for one Authorization Server cannot be relayed to another.
	//
	// Which of two readings is right is openid/OpenID4VCI#812 - the
	// normative sentence says the derived Origin, its own example shows
	// the endpoint URL. This wallet follows the sentence, as WE BUILD
	// CS-01 does.
	audience, err := interactiveAuthorizationAudience(challengeEndpoint)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	// Before anything is selected or disclosed.
	//
	// expected_origins is the Verifier naming where it expects this
	// request to be answered. Verifying the signature establishes that the
	// request was not tampered with; it does not establish that THIS
	// endpoint is the one it was written for. A signed request lifted from
	// one Authorization Server and replayed by another verifies perfectly
	// and is meant for somewhere else, and the Holder's credential is what
	// gets spent finding that out.
	if err := checkExpectedOrigins(ro, challengeEndpoint); err != nil {
		step.Error = err.Error()
		return "", err
	}

	vpTokens, presented, err := c.buildIAVPTokens(ctx, ro, vci, audience)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	payload := map[string]any{
		"vp_token": vpTokens,
		"state":    ro.State,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	// ia_post.jwt: the response is encrypted to the key the request
	// advertised. Unencrypted ia_post is not attempted even when a server
	// would accept it - the response travels back through this wallet and
	// then through a form parameter, and downgrading it silently would
	// make a test run prove less than it appears to.
	encrypted, err := encryptToRequestKey(ro, raw)
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	envelope, err := json.Marshal(map[string]string{"response": encrypted})
	if err != nil {
		step.Error = err.Error()
		return "", err
	}

	step.Detail = fmt.Sprintf("audience=%s credentials=%d", audience, presented)
	return string(envelope), nil
}

// parseInteractiveAuthorizationRequest reads the openid4vp_request member.
//
// It carries either a signed request as {"request": "<jwt>"} or the
// parameters inline. Both are accepted: the draft permits either, and a
// test wallet that handled only one would report an issuer's valid choice
// as a failure.
func (c *Client) parseInteractiveAuthorizationRequest(raw json.RawMessage) (*openid4vp.RequestObject, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("the challenge required a presentation but carried no openid4vp_request")
	}

	var signed struct {
		Request string `json:"request"`
	}
	if err := json.Unmarshal(raw, &signed); err == nil && signed.Request != "" {
		// Verified, with the same key material and the same algorithm
		// allowlist this wallet already applies to a Verifier's request
		// object in fetchRequestObject - an Issuer's is the same kind of
		// JWT arriving over the same kind of channel, and there is no
		// reason for one to be held to a weaker standard than the other.
		//
		// The earlier argument here was that a test wallet has no trust
		// anchor so verification is pointless. It does not hold: the key
		// travels in the JWT's own x5c or jwk header, so the signature
		// can be checked without one, and checking it is what makes the
		// alg allowlist mean anything. Without it a request header of
		// {"alg":"none"} was accepted and acted on - the response was
		// then encrypted to whatever key that unsigned request named.
		//
		// What a header key does NOT establish is WHOSE key it is. That
		// still needs a trust anchor, and a production wallet must have
		// one; this remains a test wallet. But "cannot establish the
		// issuer" is not a reason to also skip establishing that the
		// request arrived intact and was signed with a strong algorithm.
		claims := jwtv5.MapClaims{}
		if _, err := jwtv5.NewParser(
			jwtv5.WithValidMethods(strongSigningAlgorithms),
		).ParseWithClaims(signed.Request, claims, requestObjectKeyFunc); err != nil {
			return nil, fmt.Errorf("verifying the signed openid4vp_request: %w", err)
		}
		body, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		ro := &openid4vp.RequestObject{}
		if err := json.Unmarshal(body, ro); err != nil {
			return nil, fmt.Errorf("reading the signed openid4vp_request: %w", err)
		}
		return ro, nil
	}

	ro := &openid4vp.RequestObject{}
	if err := json.Unmarshal(raw, ro); err != nil {
		return nil, fmt.Errorf("reading the openid4vp_request: %w", err)
	}
	return ro, nil
}

// interactiveAuthorizationAudience is what a Key Binding JWT presented to
// an Authorization Challenge Endpoint must be addressed to: the "ia:"
// prefix followed by the endpoint's derived Origin (RFC 6454 §4).
func interactiveAuthorizationAudience(challengeEndpoint string) (string, error) {
	origin, err := openid4vp.CanonicalOrigin(challengeEndpoint)
	if err != nil {
		return "", fmt.Errorf("deriving the challenge endpoint origin: %w", err)
	}
	return "ia:" + origin, nil
}

// checkExpectedOrigins refuses a request that was written for somewhere
// else.
//
// The comparison is between canonical origins, not raw strings - which is
// what CanonicalOrigin exists for, and why its IDNA, IPv6, IPv4 and port
// handling matters here: a Verifier that wrote "https://ISSUER.example:443"
// means the same origin this endpoint has, and a wallet that said
// otherwise would refuse a request it should answer.
//
// An absent expected_origins is not a failure. The member is optional and
// a request that does not constrain the origin has not been relayed
// anywhere it objects to.
func checkExpectedOrigins(ro *openid4vp.RequestObject, challengeEndpoint string) error {
	if len(ro.ExpectedOrigins) == 0 {
		return nil
	}

	here, err := openid4vp.CanonicalOrigin(challengeEndpoint)
	if err != nil {
		return fmt.Errorf("deriving the challenge endpoint origin: %w", err)
	}

	for _, expected := range ro.ExpectedOrigins {
		// An entry that cannot be canonicalised is skipped rather than
		// fatal: one unusable entry in the list must not veto the others,
		// and a list with nothing usable in it still fails below.
		if origin, err := openid4vp.CanonicalOrigin(expected); err == nil && origin == here {
			return nil
		}
	}

	return fmt.Errorf(
		"the openid4vp_request expects to be answered at one of %v, but this is %s - it was written for another Authorization Server",
		ro.ExpectedOrigins, here)
}

// encryptToRequestKey encrypts the response to the key the request
// advertised in client_metadata.jwks, as Section 8.3 of OpenID4VP
// requires for an encrypted response mode.
func encryptToRequestKey(ro *openid4vp.RequestObject, payload []byte) (string, error) {
	if ro.ClientMetadata == nil || ro.ClientMetadata.JWKS == nil || len(ro.ClientMetadata.JWKS.Keys) == 0 {
		return "", fmt.Errorf("the request asked for an encrypted response but advertised no encryption key")
	}

	key, err := selectEncryptionKey(ro.ClientMetadata.JWKS.Keys)
	if err != nil {
		return "", err
	}
	public, err := publicOf(key)
	if err != nil {
		return "", err
	}

	enc, err := responseContentEncryption(ro.ClientMetadata.EncryptedResponseEncValuesSupported)
	if err != nil {
		return "", err
	}

	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(jwa.ECDH_ES(), public),
		jwe.WithContentEncryption(enc))
	if err != nil {
		return "", fmt.Errorf("encrypting the openid4vp response: %w", err)
	}
	return string(encrypted), nil
}

// selectEncryptionKey picks the first advertised key this wallet can
// encrypt to with ECDH-ES, by its properties rather than its position.
func selectEncryptionKey(keys []jwk.Key) (jwk.Key, error) {
	for _, key := range keys {
		if usableForECDHES(key) {
			return key, nil
		}
	}
	return nil, fmt.Errorf("none of the %d keys the request advertised is usable for ECDH-ES response encryption", len(keys))
}

// usableForECDHES reports whether key is an EC (P-256/384/521) or X25519
// key not restricted by alg, use or key_ops to something other than
// ECDH-ES key agreement.
func usableForECDHES(key jwk.Key) bool {
	var crv jwa.EllipticCurveAlgorithm
	switch key.KeyType() {
	case jwa.EC():
		if err := key.Get(jwk.ECDSACrvKey, &crv); err != nil {
			return false
		}
		if crv != jwa.P256() && crv != jwa.P384() && crv != jwa.P521() {
			return false
		}
	case jwa.OKP():
		if err := key.Get(jwk.OKPCrvKey, &crv); err != nil || crv != jwa.X25519() {
			return false
		}
	default:
		return false
	}

	if alg, ok := key.Algorithm(); ok && alg.String() != jwa.ECDH_ES().String() {
		return false
	}
	if use, ok := key.KeyUsage(); ok && use != string(jwk.ForEncryption) {
		return false
	}
	if ops, ok := key.KeyOps(); ok && !slices.Contains(ops, jwk.KeyOpDeriveKey) && !slices.Contains(ops, jwk.KeyOpDeriveBits) {
		return false
	}
	return true
}

// supportedContentEncryption is the JWE "enc" this wallet can produce,
// under the names encrypted_response_enc_values_supported uses.
var supportedContentEncryption = map[string]jwa.ContentEncryptionAlgorithm{
	"A128GCM":       jwa.A128GCM(),
	"A192GCM":       jwa.A192GCM(),
	"A256GCM":       jwa.A256GCM(),
	"A128CBC-HS256": jwa.A128CBC_HS256(),
	"A192CBC-HS384": jwa.A192CBC_HS384(),
	"A256CBC-HS512": jwa.A256CBC_HS512(),
}

// responseContentEncryption picks the JWE "enc" to use for the response.
//
// A256GCM was hardcoded here, which is not what the request says. OpenID4VP
// §5.1 makes encrypted_response_enc_values_supported the list a Verifier
// will accept and A128GCM the single default when the member is absent - so
// against a server that advertised nothing, this wallet emitted an A256GCM
// JWE that a conforming server is entitled to reject, and the test run
// would have reported our own non-conformance as the server's fault.
//
// The advertised order is the server's preference, so the first value this
// wallet supports is taken rather than the strongest. A list naming only
// algorithms this wallet cannot produce is an error, not a silent
// downgrade to the default: the server said what it accepts.
func responseContentEncryption(advertised []string) (jwa.ContentEncryptionAlgorithm, error) {
	if len(advertised) == 0 {
		// OpenID4VP §5.1: absent means the default single value A128GCM.
		return jwa.A128GCM(), nil
	}

	for _, name := range advertised {
		if enc, ok := supportedContentEncryption[name]; ok {
			return enc, nil
		}
	}

	return jwa.A128GCM(), fmt.Errorf(
		"the request advertised encrypted_response_enc_values_supported=%v, none of which this wallet can produce", advertised)
}

// publicOf returns the public half of an advertised key, which is what it
// should already be - a request that advertised a private key is a server
// bug worth not propagating.
func publicOf(key jwk.Key) (jwk.Key, error) {
	public, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("deriving the public encryption key: %w", err)
	}
	return public, nil
}

// buildIAVPTokens answers the request's DCQL query and returns the
// vp_token member: one entry per credential query, keyed by that query's
// id, as OpenID4VP §8.1 defines it.
//
// It used to delegate to the VP scenario's selector with no filter, which
// ignores the DCQL query entirely and returns every credential in the
// wallet. Those were then serialised as a single JSON-array string under
// the FIRST query id - a value no server can read, and one that offered
// the Issuer every unrelated credential the wallet held. A wallet must
// answer the question it was asked.
//
// The second return value is how many credentials were presented, for the
// step detail.
func (c *Client) buildIAVPTokens(ctx context.Context, ro *openid4vp.RequestObject, vci *config.VCIScenario, audience string) (map[string]any, int, error) {
	candidates, err := c.presentableCredentials(vci)
	if err != nil {
		return nil, 0, err
	}

	if ro.DCQLQuery == nil || len(ro.DCQLQuery.Credentials) == 0 {
		// Nothing said what to present. Refusing is the only honest
		// answer: guessing would put a credential in front of an Issuer
		// that never asked for one.
		return nil, 0, fmt.Errorf("the openid4vp_request carried no dcql_query, so there is nothing to answer")
	}

	answerable := map[string][]*credential.StoredCredential{}
	for _, query := range ro.DCQLQuery.Credentials {
		if matched := matchingCredentials(candidates, query); len(matched) > 0 {
			answerable[query.ID] = matched
		}
	}

	selected, err := selectCredentialQueries(ro.DCQLQuery, answerable)
	if err != nil {
		return nil, 0, err
	}

	tokens := map[string]any{}
	presented := 0
	for _, query := range ro.DCQLQuery.Credentials {
		if !selected[query.ID] {
			continue
		}
		matched := answerable[query.ID]
		if !query.Multiple {
			matched = matched[:1]
		}

		entries := make([]string, 0, len(matched))
		for _, cred := range matched {
			token, err := c.buildIAVPToken(ctx, cred.RawCredential, ro, audience)
			if err != nil {
				return nil, 0, fmt.Errorf("building the vp_token for credential query %q: %w", query.ID, err)
			}
			entries = append(entries, token)
		}
		tokens[query.ID] = entries
		presented += len(entries)
	}

	return tokens, presented, nil
}

// selectCredentialQueries decides which of the request's credential
// queries this response answers, given which of them the wallet can
// answer at all.
//
// Requiring every query is only right when credential_sets is absent -
// OpenID4VP 1.0 §6.2 makes that the default. When it is present, each set
// lists ALTERNATIVES in its options, and satisfying one option satisfies
// the set. Our own issuer builds exactly that: buildIssuanceAuthDCQL puts
// each authentication scope in its own option, so a deployment offering
// two ways to authenticate produced a request this wallet refused unless
// the Holder happened to carry both credentials.
//
// A required set with no satisfiable option is reported, naming the set.
// An optional one is skipped, which is what optional means.
//
// A query no set references is NOT presented. OpenID4VP 1.0 §6.4.2 asks
// for the required sets to be satisfied and nothing more, so once
// credential_sets is present it is the whole statement of what the
// Verifier wants - `credentials` is the pool those sets draw from, not a
// second list of demands. Presenting an unreferenced credential anyway
// would disclose one the Verifier never asked for, which is the wrong way
// round for a Holder.
func selectCredentialQueries(dcql *openid4vp.DCQL, answerable map[string][]*credential.StoredCredential) (map[string]bool, error) {
	selected := map[string]bool{}

	if len(dcql.CredentialSets) == 0 {
		for _, query := range dcql.Credentials {
			if _, ok := answerable[query.ID]; !ok {
				return nil, fmt.Errorf("no credential in this wallet satisfies the credential query %q", query.ID)
			}
			selected[query.ID] = true
		}
		return selected, nil
	}

	for setIndex, set := range dcql.CredentialSets {
		chosen := []string(nil)
		for _, option := range set.Options {
			if optionIsAnswerable(option, answerable) {
				chosen = option
				break
			}
		}

		if chosen == nil {
			if set.IsRequired() {
				return nil, fmt.Errorf(
					"no credential in this wallet satisfies any option of required credential set %d", setIndex)
			}
			continue
		}
		for _, id := range chosen {
			selected[id] = true
		}
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("the request's credential sets are all optional and this wallet satisfies none of them")
	}
	return selected, nil
}

// optionIsAnswerable reports whether every credential query in one
// credential-set option can be answered. An option is all-or-nothing:
// half of an alternative satisfies nothing.
func optionIsAnswerable(option []string, answerable map[string][]*credential.StoredCredential) bool {
	if len(option) == 0 {
		return false
	}
	for _, id := range option {
		if _, ok := answerable[id]; !ok {
			return false
		}
	}
	return true
}

// presentableCredentials is the pool the DCQL query is matched against:
// the whole store, or the one credential the scenario named.
//
// A scenario that names a credential is driving a specific case, so a
// named credential that does not satisfy the query is reported as the
// query not being satisfiable rather than silently replaced.
func (c *Client) presentableCredentials(vci *config.VCIScenario) ([]*credential.StoredCredential, error) {
	if vci.PresentCredential == "" {
		return c.store.List(), nil
	}
	cred, ok := c.store.Get(vci.PresentCredential)
	if !ok {
		return nil, fmt.Errorf("credential %q named by present_credential is not in this wallet", vci.PresentCredential)
	}
	return []*credential.StoredCredential{cred}, nil
}

// matchingCredentials is DCQL §6.1 matching: the format, the
// format-specific type constraint, and the claims and claim_sets.
//
// Each match is a copy whose RawCredential is reduced to the disclosures
// the query asks for (§6.4.1), so the key-binding hash covers only what is
// presented. A credential this wallet cannot reduce - anything but an
// SD-JWT - does not match a claim-constrained query, which leaves any
// credential-set alternative usable.
func matchingCredentials(candidates []*credential.StoredCredential, query openid4vp.CredentialQuery) []*credential.StoredCredential {
	var matched []*credential.StoredCredential
	for _, cred := range candidates {
		if query.Format != "" && normalisedFormat(cred.Format) != normalisedFormat(query.Format) {
			continue
		}
		if !credentialTypeMatches(cred, query) {
			continue
		}
		reduced, ok := selectClaims(cred.RawCredential, query)
		if !ok {
			if len(query.Claims) > 0 {
				continue
			}
			// Not an SD-JWT and nothing was asked of its claims.
			reduced = cred.RawCredential
		}
		presented := *cred
		presented.RawCredential = reduced
		matched = append(matched, &presented)
	}
	return matched
}

// normalisedFormat folds the two spellings of SD-JWT VC together.
//
// "dc+sd-jwt" is the current identifier and the one a DCQL query carries;
// "vc+sd-jwt" is the legacy one, and it is what this wallet's own
// detectFormat records for every credential it is issued. Comparing them
// literally meant a credential obtained through issuance could never
// satisfy a presentation request for the very type it is - the IA tests
// only passed because their fixture writes the new spelling by hand.
//
// The repository already treats the two as one format elsewhere; see
// CredentialMetadata.DCQLMetaQuery, which accepts both for the same
// reason.
func normalisedFormat(format string) string {
	if format == "vc+sd-jwt" {
		return openid4vp.FormatSDJWTVC
	}
	return format
}

// credentialTypeMatches applies the format-specific meta constraint.
//
// A query that constrains the type and a credential whose type cannot be
// determined do not match. Presenting it anyway would be answering a
// question nobody asked - the fail-closed reading is the only one that
// keeps an unrelated credential out of the response.
func credentialTypeMatches(cred *credential.StoredCredential, query openid4vp.CredentialQuery) bool {
	switch {
	case len(query.Meta.VCTValues) > 0:
		return slices.Contains(query.Meta.VCTValues, credentialVCT(cred))
	case query.Meta.DoctypeValue != "":
		return credentialVCT(cred) == query.Meta.DoctypeValue
	case len(query.Meta.TypeValues) > 0:
		// This wallet does not read W3C credential types yet; matching
		// nothing keeps an unrelated credential of the format out.
		return false
	default:
		return true
	}
}

// credentialVCT is the type of a stored credential.
//
// The store records one when whoever put the credential there knew it,
// which issuance does not: runVCIScenario stores what the Issuer returned
// without reading it. So the vct claim is recovered from the credential
// itself when the field is empty, because a wallet that cannot say what
// it holds cannot answer a DCQL query about it.
//
// Only an SD-JWT VC is recovered from. An mdoc's doctype lives in CBOR
// that would have to be decoded to reach, and this wallet cannot build an
// mdoc presentation anyway - buildVPToken handles SD-JWT and returns the
// raw credential for everything else. So an mdoc whose doctype the store
// did not record fails a doctype_value query by name, which is the
// failure a test wallet should report rather than quietly presenting
// something it could not identify.
func credentialVCT(cred *credential.StoredCredential) string {
	if cred.VCT != "" {
		return cred.VCT
	}

	// An SD-JWT VC presentation is <jwt>~<disclosure>~...; the type is a
	// claim of the issuer-signed JWT at the front.
	jwtPart, _, _ := strings.Cut(cred.RawCredential, "~")
	parts := strings.Split(jwtPart, ".")
	if len(parts) != 3 {
		return ""
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		VCT     string `json:"vct"`
		DocType string `json:"docType"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return ""
	}
	if claims.VCT != "" {
		return claims.VCT
	}
	return claims.DocType
}

// buildIAVPToken builds the VP token with the Interactive Authorization
// audience rather than the request's client_id.
func (c *Client) buildIAVPToken(ctx context.Context, rawCredential string, ro *openid4vp.RequestObject, audience string) (string, error) {
	// buildVPToken binds the Key Binding JWT to ro.ClientID. For this
	// flow the audience is the prefixed challenge endpoint instead, so
	// the request object is copied with that substituted rather than
	// duplicating the token-building logic.
	bound := *ro
	bound.ClientID = audience
	return c.buildVPToken(ctx, []string{rawCredential}, &bound, &config.VPScenario{})
}
