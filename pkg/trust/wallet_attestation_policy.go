package trust

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	spocp "github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// WalletAttestationPolicyEngine wraps a SPOCP engine for wallet attestation tier authorization.
// When nil, all trusted wallets are authorized (default open).
type WalletAttestationPolicyEngine struct {
	mu     sync.RWMutex
	engine *spocp.AdaptiveEngine
}

// BuildWalletAttestationPolicyQuery constructs a SPOCP query for wallet attestation authorization.
// Query format: (wallet (attestation_source <tier>)(scope <scope>)(issuer <provider>))
func BuildWalletAttestationPolicyQuery(attestationSource, scope, issuer string) sexp.Element {
	if attestationSource == "" {
		attestationSource = "unknown"
	}
	if scope == "" {
		scope = "*"
	}
	if issuer == "" {
		issuer = "*"
	}
	return sexp.NewList("wallet",
		sexp.NewList("attestation_source", sexp.NewAtom(attestationSource)),
		sexp.NewList("scope", sexp.NewAtom(scope)),
		sexp.NewList("issuer", sexp.NewAtom(issuer)),
	)
}

// Authorize checks if the given attestation tier is authorized for the requested scope.
// Returns true if no policy engine is configured (default open).
func (e *WalletAttestationPolicyEngine) Authorize(attestationSource, scope, issuer string) bool {
	if e == nil {
		return true // default open
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	query := BuildWalletAttestationPolicyQuery(attestationSource, scope, issuer)
	return e.engine.QueryElement(query)
}

// RuleCount returns the number of loaded rules, or 0 if engine is nil.
func (e *WalletAttestationPolicyEngine) RuleCount() int {
	if e == nil {
		return 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.engine.RuleCount()
}

// BuildWalletAttestationPolicyEngine creates a SPOCP engine from rules configuration.
// Returns nil when no rules are configured (default open — all trusted wallets authorized).
func BuildWalletAttestationPolicyEngine(rules []string, rulesFile string) (*WalletAttestationPolicyEngine, error) {
	if len(rules) == 0 && rulesFile == "" {
		return nil, nil // default open
	}

	engine := spocp.New()

	for i, r := range rules {
		elem, err := sexp.NewParser(r).Parse()
		if err != nil {
			return nil, fmt.Errorf("invalid wallet attestation policy rule #%d: %w", i+1, err)
		}
		engine.AddRuleElement(elem)
	}

	if rulesFile != "" {
		if err := loadWalletPolicyRulesFromFile(engine, rulesFile); err != nil {
			return nil, err
		}
	}

	return &WalletAttestationPolicyEngine{engine: engine}, nil
}

func loadWalletPolicyRulesFromFile(engine *spocp.AdaptiveEngine, path string) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("open wallet attestation policy file %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		elem, err := sexp.NewParser(line).Parse()
		if err != nil {
			return fmt.Errorf("wallet attestation policy file %s line %d: %w", path, lineNum, err)
		}
		engine.AddRuleElement(elem)
	}
	return scanner.Err()
}
