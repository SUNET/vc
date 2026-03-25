package httphelpers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"unicode"
	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	spocp "github.com/sirosfoundation/go-spocp"
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

// buildSPOCPEngine creates a SPOCP engine from the JWT config rules.
// Returns nil when no rules are configured (authentication-only mode).
func buildSPOCPEngine(cfg model.APIAuthJWT) (*SafeEngine, error) {
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

// loadRulesFromFile reads human-readable SPOCP rules (one per line) from a file
// and adds them to the engine using parseAdvancedSExp.
func loadRulesFromFile(engine *spocp.AdaptiveEngine, path string) error {
	f, err := os.Open(path)
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

// buildSPOCPQuery constructs a SPOCP query S-expression for the current HTTP
// request, service name, and JWT subject:
//
//	(api (service apigw)(method POST)(path /api/v1/upload)(subject alice))
//
// The service dimension ensures that rules written for one service do not
// accidentally grant access to another service sharing the same endpoints.
func buildSPOCPQuery(service, method, path, subject string) sexp.Element {
	return sexp.NewList("api",
		sexp.NewList("service", sexp.NewAtom(service)),
		sexp.NewList("method", sexp.NewAtom(method)),
		sexp.NewList("path", sexp.NewAtom(path)),
		sexp.NewList("subject", sexp.NewAtom(subject)),
	)
}

// JWTAuth returns a Gin middleware that validates Bearer JWT tokens and
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
// "jwt_claims" and the "sub" claim is stored under "jwt_subject".
func (m *middlewareHandler) JWTAuth(ctx context.Context, service string, cfg model.APIAuthJWT, jwksCache JWKSCache, engine *SafeEngine) gin.HandlerFunc {
	_, span := m.client.tracer.Start(ctx, "httphelpers:middleware:JWTAuth")
	defer span.End()

	log := m.log.New("jwt_auth")

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

		sub, _ := token.Subject()

		// SPOCP authorization check (if rules are configured).
		if engine != nil {
			query := buildSPOCPQuery(service, c.Request.Method, c.FullPath(), sub)
			if !engine.QueryElement(query) {
				log.Info("spocp_denied", "subject", sub, "service", service, "method", c.Request.Method, "path", c.FullPath(), "req_id", c.GetString("req_id"))
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
				return
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
//   - If JWT.Enable is true  – Bearer JWT authentication + optional SPOCP authz
//   - If BasicAuth.Enable is true – HTTP Basic authentication (allow/deny)
//   - If neither is enabled – no authentication (open access)
//
// Only one of JWT.Enable and BasicAuth.Enable may be true.
//
// The service parameter identifies the logical service (e.g. "apigw", "issuer")
// and is included in SPOCP queries so that rules written for one service
// do not accidentally grant access to another.
func (m *middlewareHandler) APIAuth(ctx context.Context, service string, apiAuth model.APIAuth, jwksCache JWKSCache) gin.HandlerFunc {
	if apiAuth.JWT.Enable && apiAuth.BasicAuth.Enable {
		panic("api_auth: both jwt.enable and basic_auth.enable are true; only one may be enabled")
	}

	switch {
	case apiAuth.JWT.Enable:
		if jwksCache == nil {
			panic("api_auth: jwt.enable is true but no JWKS cache was provided")
		}

		engine, err := buildSPOCPEngine(apiAuth.JWT)
		if err != nil {
			panic(fmt.Sprintf("api_auth: failed to build SPOCP engine: %v", err))
		}

		if engine != nil {
			m.log.Info("api_auth_mode", "mode", "jwt+spocp", "jwks_url", apiAuth.JWT.JWKSURL, "rules", engine.RuleCount())
		} else {
			m.log.Info("api_auth_mode", "mode", "jwt", "jwks_url", apiAuth.JWT.JWKSURL)
		}
		return m.JWTAuth(ctx, service, apiAuth.JWT, jwksCache, engine)

	case apiAuth.BasicAuth.Enable:
		m.log.Info("api_auth_mode", "mode", "basic")
		return m.BasicAuth(ctx, apiAuth.BasicAuth.Users)

	default:
		m.log.Info("api_auth_mode", "mode", "none")
		return func(c *gin.Context) {
			c.Next()
		}
	}
}
