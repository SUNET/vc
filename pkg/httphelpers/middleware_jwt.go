package httphelpers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	spocp "github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/compare"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"
)

// JWKSCache is the generic cache interface used to store raw JWKS JSON.
// It is satisfied by both MemoryCache and MongoCache from pkg/cache.
type JWKSCache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, value []byte)
}

// getKeys retrieves the JWKS keyset, using the cache for the raw JSON.
// On cache miss it fetches from the URL and stores the result.
func getKeys(ctx context.Context, url string, c JWKSCache, log func(string, ...any)) (jwk.Set, error) {
	// Try cache first.
	if raw, ok := c.Get(ctx, url); ok {
		set, err := jwk.Parse(raw)
		if err == nil {
			return set, nil
		}
		// Cached data is corrupt – fall through to re-fetch.
		log("jwks_cache_parse_failed, re-fetching", "error", err, "url", url)
	}

	// Fetch from remote.
	set, err := jwk.Fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", url, err)
	}

	// Serialize and store in cache.
	raw, err := json.Marshal(set)
	if err == nil {
		c.Set(ctx, url, raw)
	} else {
		log("jwks_marshal_for_cache_failed", "error", err, "url", url)
	}

	log("jwks_refreshed", "url", url, "key_count", set.Len())
	return set, nil
}

// SafeEngine wraps a SPOCP AdaptiveEngine with a sync.RWMutex so that
// concurrent request handlers can safely call QueryElement while still
// allowing future rule hot-reloading under a write lock.
type SafeEngine struct {
	mu     sync.RWMutex
	engine *spocp.AdaptiveEngine
}

// QueryElement checks if the query is authorized (read-locked).
func (s *SafeEngine) QueryElement(q sexp.Element) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.engine.QueryElement(q)
}

// RuleCount returns the number of loaded rules (read-locked).
func (s *SafeEngine) RuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.engine.RuleCount()
}

// BuildSPOCPEngine creates a SPOCP engine from the APIAuth rules.
// Returns nil when no rules are configured (authentication-only mode).
func BuildSPOCPEngine(cfg model.APIAuth) (*SafeEngine, error) {
	hasInline := len(cfg.Rules) > 0
	hasFile := cfg.RulesFile != ""

	if !hasInline && !hasFile {
		return nil, nil
	}

	engine := spocp.New()

	for i, r := range cfg.Rules {
		elem, err := parseAdvancedSExp(r)
		if err != nil {
			return nil, fmt.Errorf("invalid inline SPOCP rule #%d: %w", i+1, err)
		}
		engine.AddRuleElement(elem)
	}

	if hasFile {
		if err := loadRulesFromFile(engine, cfg.RulesFile); err != nil {
			return nil, fmt.Errorf("failed to load SPOCP rules from %s: %w", cfg.RulesFile, err)
		}
	}

	return &SafeEngine{engine: engine}, nil
}

// parseRulesFile parses a rules file and returns the elements (best-effort)
func parseRulesFile(path string) []sexp.Element {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil
	}
	defer f.Close()

	var elems []sexp.Element
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		elem, err := parseAdvancedSExp(line)
		if err != nil {
			continue
		}
		elems = append(elems, elem)
	}
	return elems
}

// loadRulesFromFile reads human-readable SPOCP rules (one per line) from a file
// and adds them to the engine using parseAdvancedSExp.
func loadRulesFromFile(engine *spocp.AdaptiveEngine, path string) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip blanks and comments
		}
		elem, err := parseAdvancedSExp(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNum, err)
		}
		engine.AddRuleElement(elem)
	}
	return scanner.Err()
}

// parseAdvancedSExp parses a human-readable ("advanced form") S-expression into
// a sexp.Element. This allows users to write rules as:
//
//	(api (method POST)(path /api/v1/upload)(subject alice))
//
// instead of canonical form:
//
//	(3:api(6:method4:POST)(4:path15:/api/v1/upload)(7:subject5:alice))
//
// It also supports star forms:
//
//	(*)                        → wildcard
//	(* prefix /api/v1/)        → prefix match
//	(* suffix .pdf)            → suffix match
//	(* set read write delete)  → set match
func parseAdvancedSExp(input string) (sexp.Element, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("empty S-expression")
	}

	p := &advancedParser{input: []rune(input), pos: 0}
	elem, err := p.parse()
	if err != nil {
		return nil, err
	}

	// Ensure we consumed all input.
	p.skipWhitespace()
	if p.pos < len(p.input) {
		return nil, fmt.Errorf("unexpected trailing input at position %d", p.pos)
	}
	return elem, nil
}

type advancedParser struct {
	input []rune
	pos   int
}

func (p *advancedParser) skipWhitespace() {
	for p.pos < len(p.input) && unicode.IsSpace(p.input[p.pos]) {
		p.pos++
	}
}

func (p *advancedParser) parse() (sexp.Element, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unexpected end of input")
	}

	if p.input[p.pos] == '(' {
		return p.parseList()
	}
	return p.parseAtom()
}

func (p *advancedParser) parseAtom() (*sexp.Atom, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unexpected end of input, expected atom")
	}

	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] != '(' && p.input[p.pos] != ')' && !unicode.IsSpace(p.input[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return nil, fmt.Errorf("empty atom at position %d", start)
	}
	return sexp.NewAtom(string(p.input[start:p.pos])), nil
}

func (p *advancedParser) parseList() (sexp.Element, error) {
	if p.input[p.pos] != '(' {
		return nil, fmt.Errorf("expected '(' at position %d", p.pos)
	}
	p.pos++ // skip '('

	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unclosed '('")
	}

	// Parse the tag atom.
	tag, err := p.parseAtom()
	if err != nil {
		return nil, fmt.Errorf("failed to parse list tag: %w", err)
	}

	// Handle star forms: tag == "*"
	if tag.Value == "*" {
		return p.parseStarForm()
	}

	// Parse remaining elements until ')'.
	var elements []sexp.Element
	for {
		p.skipWhitespace()
		if p.pos >= len(p.input) {
			return nil, fmt.Errorf("unclosed list '%s'", tag.Value)
		}
		if p.input[p.pos] == ')' {
			p.pos++ // skip ')'
			return sexp.NewList(tag.Value, elements...), nil
		}
		elem, err := p.parse()
		if err != nil {
			return nil, err
		}
		// Treat a bare * inside a tagged list as a wildcard star form,
		// so (method *) is equivalent to (method (*)).
		// Treat a trailing * (e.g. /api/v1/*) as a prefix star form,
		// so (path /api/v1/*) is equivalent to (path (* prefix /api/v1/)).
		if atom, ok := elem.(*sexp.Atom); ok {
			if atom.Value == "*" {
				elem = &starform.Wildcard{}
			} else if before, found := strings.CutSuffix(atom.Value, "*"); found {
				elem = &starform.Prefix{Value: before}
			}
		}
		elements = append(elements, elem)
	}
}

// parseStarForm parses the body of a star form after the '*' tag.
// At this point the opening '(' and '*' have been consumed.
func (p *advancedParser) parseStarForm() (sexp.Element, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unclosed star form")
	}

	// (*) → wildcard
	if p.input[p.pos] == ')' {
		p.pos++
		return &starform.Wildcard{}, nil
	}

	// Read the star form type: set, prefix, suffix, range...
	formType, err := p.parseAtom()
	if err != nil {
		return nil, fmt.Errorf("failed to parse star form type: %w", err)
	}

	switch formType.Value {
	case "prefix":
		return p.parsePrefixSuffix(true)
	case "suffix":
		return p.parsePrefixSuffix(false)
	case "set":
		return p.parseSet()
	default:
		return nil, fmt.Errorf("unsupported star form type %q", formType.Value)
	}
}

func (p *advancedParser) parsePrefixSuffix(isPrefix bool) (sexp.Element, error) {
	p.skipWhitespace()
	value, err := p.parseAtom()
	if err != nil {
		return nil, fmt.Errorf("expected value for prefix/suffix star form: %w", err)
	}
	p.skipWhitespace()
	if p.pos >= len(p.input) || p.input[p.pos] != ')' {
		return nil, fmt.Errorf("expected ')' to close prefix/suffix star form")
	}
	p.pos++
	if isPrefix {
		return &starform.Prefix{Value: value.Value}, nil
	}
	return &starform.Suffix{Value: value.Value}, nil
}

func (p *advancedParser) parseSet() (sexp.Element, error) {
	var elements []sexp.Element
	for {
		p.skipWhitespace()
		if p.pos >= len(p.input) {
			return nil, fmt.Errorf("unclosed set star form")
		}
		if p.input[p.pos] == ')' {
			p.pos++
			if len(elements) == 0 {
				return nil, fmt.Errorf("empty set star form")
			}
			return &starform.Set{Elements: elements}, nil
		}
		elem, err := p.parse()
		if err != nil {
			return nil, err
		}
		elements = append(elements, elem)
	}
}

// extractSPOCPSubject returns the identity to use as the SPOCP subject
// from a validated JWT, preferring eppn → email
func extractSPOCPSubject(token jwt.Token) string {
	var s string
	if err := token.Get("eppn", &s); err == nil && s != "" {
		return s
	}
	if err := token.Get("email", &s); err == nil && s != "" {
		return s
	}
	return ""
}

// BuildSPOCPQuery constructs a SPOCP query S-expression for the current HTTP
// request, including service, method, path, subject, authentic source and scope:
//
//	(vc (service apigw)(method POST)(path /api/v1/upload)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))
//
// The service dimension ensures that rules written for one service do not
// accidentally grant access to another service sharing the same endpoints.
func BuildSPOCPQuery(service, method, path, subject, authenticSource, scope string) sexp.Element {
	elements := []sexp.Element{
		sexp.NewList("service", sexp.NewAtom(service)),
		sexp.NewList("method", sexp.NewAtom(method)),
		sexp.NewList("path", sexp.NewAtom(path)),
		sexp.NewList("subject", sexp.NewAtom(subject)),
	}
	if authenticSource != "" {
		elements = append(elements, sexp.NewList("authentic_source", sexp.NewAtom(authenticSource)))
	}
	if scope != "" {
		elements = append(elements, sexp.NewList("scope", sexp.NewAtom(scope)))
	}
	return sexp.NewList("vc", elements...)
}

// ResourcePair represents an allowed (authentic_source, scope) combination.
type ResourcePair struct {
	AuthenticSource string
	Scope           string
}

// ResolveAllowedResources returns all (authentic_source, scope) pairs that the
// given subject is authorized for, by inspecting the SPOCP rules directly.
// A wildcard in the rule position means "any value" — represented as "*" in the result.
// Returns nil when engine is nil (no authorization configured).
func ResolveAllowedResources(engine *SafeEngine, subject string) []ResourcePair {
	if engine == nil {
		return nil
	}

	subjectQuery := sexp.NewList("subject", sexp.NewAtom(subject))

	engine.mu.RLock()
	defer engine.mu.RUnlock()
	rules := engine.engine.ExportRules()

	var pairs []ResourcePair
	for _, rule := range rules {
		ruleList, ok := rule.(*sexp.List)
		if !ok || ruleList.Tag != "vc" || len(ruleList.Elements) < 6 {
			continue
		}
		// Check if the subject element (position 3) matches.
		subjectRule := ruleList.Elements[3]
		if !compare.LessPermissive(subjectQuery, subjectRule) {
			continue
		}
		// Extract authentic_source (position 4) and scope (position 5).
		// Sets expand into multiple pairs.
		sources := extractListValues(ruleList.Elements[4])
		scopes := extractListValues(ruleList.Elements[5])
		for _, as := range sources {
			for _, sc := range scopes {
				pairs = append(pairs, ResourcePair{AuthenticSource: as, Scope: sc})
			}
		}
	}
	return pairs
}

// extractListValues extracts string values from a list element like (authentic_source SUNET).
// Returns ["*"] for wildcards. Expands sets into multiple values.
func extractListValues(elem sexp.Element) []string {
	list, ok := elem.(*sexp.List)
	if !ok || len(list.Elements) == 0 {
		return []string{"*"}
	}
	switch v := list.Elements[0].(type) {
	case *sexp.Atom:
		return []string{v.Value}
	case *starform.Wildcard:
		return []string{"*"}
	case *starform.Set:
		var values []string
		for _, el := range v.Elements {
			if a, ok := el.(*sexp.Atom); ok {
				values = append(values, a.Value)
			}
		}
		if len(values) == 0 {
			return []string{"*"}
		}
		return values
	default:
		return []string{"*"}
	}
}

// AllowedAuthenticSources returns the distinct authentic_source values the subject
// is permitted to access. Returns nil for unrestricted access (wildcard rule or no resource rules).
func AllowedAuthenticSources(engine *SafeEngine, subject string) []string {
	pairs := ResolveAllowedResources(engine, subject)
	if len(pairs) == 0 {
		return nil // no resource constraints — unrestricted
	}
	seen := map[string]bool{}
	var result []string
	for _, p := range pairs {
		if p.AuthenticSource == "*" {
			return nil // unrestricted
		}
		if !seen[p.AuthenticSource] {
			seen[p.AuthenticSource] = true
			result = append(result, p.AuthenticSource)
		}
	}
	return result
}

// AllowedScopes returns the distinct scope values the subject is permitted to
// access. Returns nil for unrestricted access (wildcard rule or no resource rules).
func AllowedScopes(engine *SafeEngine, subject string) []string {
	pairs := ResolveAllowedResources(engine, subject)
	if len(pairs) == 0 {
		return nil // no resource constraints — unrestricted
	}
	seen := map[string]bool{}
	var result []string
	for _, p := range pairs {
		if p.Scope == "*" {
			return nil // unrestricted
		}
		if !seen[p.Scope] {
			seen[p.Scope] = true
			result = append(result, p.Scope)
		}
	}
	return result
}

// JWKSAuth returns a Gin middleware that validates Bearer JWT tokens and
// optionally checks SPOCP authorization rules.
//
// The middleware extracts the token from the Authorization header, validates
// its signature against the JWKS at the configured URL, and verifies the
// standard "iss" and "aud" claims.
//
// When a SPOCP engine is provided (non-nil), the middleware additionally
// checks whether the request (method + path + subject) is authorized.
//
// On success the parsed claims are stored in the Gin context under the key
// "jwt_claims" and the subject identity (resolved from the "eppn" or "email"
// claim, not the standard "sub" claim) is stored under "jwt_subject".
func (m *middlewareHandler) JWKSAuth(ctx context.Context, service string, cfg model.APIAuthJWKS, jwksCache JWKSCache, engine *SafeEngine) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:JWKSAuth")
	defer span.End()

	log := m.log.New("jwks_auth")

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header, expected Bearer token"})
			return
		}
		tokenStr := parts[1]

		keys, err := getKeys(c.Request.Context(), cfg.JWKSURL, jwksCache, func(msg string, args ...any) {
			log.Info(msg, args...)
		})
		if err != nil {
			log.Error(err, "jwks_fetch_error")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "unable to validate token"})
			return
		}

		token, err := jwt.Parse(
			[]byte(tokenStr),
			jwt.WithKeySet(keys),
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(cfg.Audience),
		)
		if err != nil {
			log.Info("jwt_validation_failed", "error", err, "req_id", c.GetString("req_id"))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		sub := extractSPOCPSubject(token)

		// SPOCP authorization check (only if rules are configured)
		if engine != nil {
			if sub == "" {
				log.Info("jwt_missing_identity", "error", "token has no eppn or email claim", "req_id", c.GetString("req_id"))
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token missing eppn or email claim"})
				return
			}

			// Store allowed authentic sources and scopes for downstream handlers (DB filtering).
			allowed := AllowedAuthenticSources(engine, sub)
			c.Set("spocp_allowed_authentic_sources", allowed)
			allowedScopes := AllowedScopes(engine, sub)
			c.Set("spocp_allowed_scopes", allowedScopes)

			// Resource access: every resource-bearing request must include
			// both authentic_source and scope so the full SPOCP query is used.
			pairs := extractResourcePairs(c)
			for _, p := range pairs {
				if p.authenticSource == "" && p.scope == "" {
					continue
				}
				query := BuildSPOCPQuery(service, c.Request.Method, c.FullPath(), sub, p.authenticSource, p.scope)
				if !engine.QueryElement(query) {
					log.Info("spocp_denied", "subject", sub, "service", service, "method", c.Request.Method, "path", c.FullPath(),
						"authentic_source", p.authenticSource, "scope", p.scope, "req_id", c.GetString("req_id"))
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions for resource"})
					return
				}
			}
		}

		c.Set("jwt_claims", token)
		c.Set("jwt_subject", sub)

		c.Next()
		log.Info("jwt_auth", "subject", sub, "req_id", c.GetString("req_id"))
	}
}

// APIAuth returns a Gin middleware that applies the authentication method
// configured in APIAuth:
//
//   - If JWKS.Enable is true – Bearer JWT authentication against a static JWKS URL
//   - If OIDC.Enable is true – Bearer JWT authentication via auto-discovered JWKS
//   - If neither is enabled  – no authentication (open access)
//
// JWKS and OIDC are mutually exclusive.
// SPOCP rules (if configured) apply to whichever mode is active.
//
// The service parameter identifies the logical service (e.g. "apigw", "issuer")
// and is included in SPOCP queries so that rules written for one service
// do not accidentally grant access to another.
func (m *middlewareHandler) APIAuth(ctx context.Context, service string, apiAuth model.APIAuth, jwksCache JWKSCache) (gin.HandlerFunc, error) {
	// Build SPOCP engine from top-level rules (applies to either auth mode).
	engine, err := BuildSPOCPEngine(apiAuth)
	if err != nil {
		return nil, fmt.Errorf("api_auth: failed to build SPOCP engine: %w", err)
	}

	switch {
	case apiAuth.JWKS.Enable:
		if jwksCache == nil {
			return nil, fmt.Errorf("api_auth: jwks.enable is true but no JWKS cache was provided")
		}
		if engine != nil {
			m.log.Info("api_auth_mode", "mode", "jwks+spocp", "jwks_url", apiAuth.JWKS.JWKSURL, "rules", engine.RuleCount())
		} else {
			m.log.Info("api_auth_mode", "mode", "jwks", "jwks_url", apiAuth.JWKS.JWKSURL)
		}
		return m.JWKSAuth(ctx, service, apiAuth.JWKS, jwksCache, engine), nil

	case apiAuth.OIDC.Enable:
		jwksURL, err := discoverJWKSURL(ctx, apiAuth.OIDC.IssuerURL)
		if err != nil {
			return nil, fmt.Errorf("api_auth: oidc discovery failed for %s: %w", apiAuth.OIDC.IssuerURL, err)
		}
		if jwksCache == nil {
			return nil, fmt.Errorf("api_auth: oidc.enable is true but no JWKS cache was provided")
		}
		if engine != nil {
			m.log.Info("api_auth_mode", "mode", "oidc+spocp", "issuer", apiAuth.OIDC.IssuerURL, "jwks_uri", jwksURL, "rules", engine.RuleCount())
		} else {
			m.log.Info("api_auth_mode", "mode", "oidc", "issuer", apiAuth.OIDC.IssuerURL, "jwks_uri", jwksURL)
		}
		oidcCfg := model.APIAuthJWKS{
			Enable:   true,
			JWKSURL:  jwksURL,
			Issuer:   apiAuth.OIDC.IssuerURL,
			Audience: apiAuth.OIDC.Audience,
		}
		return m.JWKSAuth(ctx, service, oidcCfg, jwksCache, engine), nil

	default:
		m.log.Info("api_auth_mode", "mode", "none")
		return func(c *gin.Context) {
			c.Next()
		}, nil
	}
}

// discoverJWKSURL fetches the OIDC discovery document and returns the jwks_uri.
func discoverJWKSURL(ctx context.Context, issuerURL string) (string, error) {
	wellKnown := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create discovery request: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("failed to decode discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery document has no jwks_uri")
	}
	return doc.JWKSURI, nil
}
