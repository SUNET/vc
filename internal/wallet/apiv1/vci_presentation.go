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

// encryptToRequestKey encrypts the response to the key the request
// advertised in client_metadata.jwks, as Section 8.3 of OpenID4VP
// requires for an encrypted response mode.
func encryptToRequestKey(ro *openid4vp.RequestObject, payload []byte) (string, error) {
	if ro.ClientMetadata == nil || ro.ClientMetadata.JWKS == nil || len(ro.ClientMetadata.JWKS.Keys) == 0 {
		return "", fmt.Errorf("the request asked for an encrypted response but advertised no encryption key")
	}

	key := ro.ClientMetadata.JWKS.Keys[0]
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
	supported := map[string]jwa.ContentEncryptionAlgorithm{
		"A128GCM":       jwa.A128GCM(),
		"A192GCM":       jwa.A192GCM(),
		"A256GCM":       jwa.A256GCM(),
		"A128CBC-HS256": jwa.A128CBC_HS256(),
		"A192CBC-HS384": jwa.A192CBC_HS384(),
		"A256CBC-HS512": jwa.A256CBC_HS512(),
	}

	if len(advertised) == 0 {
		// OpenID4VP §5.1: absent means the default single value A128GCM.
		return jwa.A128GCM(), nil
	}

	for _, name := range advertised {
		if enc, ok := supported[name]; ok {
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

	tokens := map[string]any{}
	presented := 0
	for _, query := range ro.DCQLQuery.Credentials {
		matched := matchingCredentials(candidates, query)
		if len(matched) == 0 {
			return nil, 0, fmt.Errorf("no credential in this wallet satisfies the credential query %q", query.ID)
		}
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

// matchingCredentials is DCQL §6.1 matching, to the extent a wallet
// holding raw credentials can perform it: the format, and the
// format-specific type constraint.
//
// Claims-level constraints are not applied. This wallet presents whole
// credentials rather than computing a disclosure subset, so a credential
// of the right type either satisfies the claim query or the Issuer will
// say so - which, for a test wallet, is the more useful outcome than
// refusing locally and reporting nothing.
func matchingCredentials(candidates []*credential.StoredCredential, query openid4vp.CredentialQuery) []*credential.StoredCredential {
	var matched []*credential.StoredCredential
	for _, cred := range candidates {
		if query.Format != "" && cred.Format != query.Format {
			continue
		}
		if !credentialTypeMatches(cred, query) {
			continue
		}
		matched = append(matched, cred)
	}
	return matched
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
