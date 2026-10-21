package apiv1

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
)

// sdJWT is an SD-JWT split into what claim selection needs: the issuer
// payload and the disclosures keyed by their digest.
type sdJWT struct {
	issuerJWT   string
	payload     map[string]any
	disclosures []string
	byDigest    map[string]sdDisclosure
}

type sdDisclosure struct {
	raw   string
	name  string
	value any
}

func parseSDJWT(raw string) (*sdJWT, error) {
	parts := strings.Split(raw, "~")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not an SD-JWT")
	}
	segments := strings.Split(parts[0], ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("issuer-signed JWT is malformed")
	}
	body, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, fmt.Errorf("decoding issuer-signed JWT payload: %w", err)
	}
	payload := map[string]any{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("reading issuer-signed JWT payload: %w", err)
	}

	alg, _ := payload["_sd_alg"].(string)
	if alg == "" {
		alg = "sha-256"
	}
	hasher, err := sdjwtvc.HashFromAlgorithm(alg)
	if err != nil {
		return nil, err
	}

	sd := &sdJWT{issuerJWT: parts[0], payload: payload, byDigest: map[string]sdDisclosure{}}
	for _, d := range parts[1:] {
		if d == "" {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			return nil, fmt.Errorf("decoding disclosure: %w", err)
		}
		var fields []any
		if err := json.Unmarshal(decoded, &fields); err != nil {
			return nil, fmt.Errorf("reading disclosure: %w", err)
		}
		disc := sdDisclosure{raw: d}
		switch len(fields) {
		case 3:
			disc.name, _ = fields[1].(string)
			disc.value = fields[2]
		case 2:
			disc.value = fields[1]
		default:
			return nil, fmt.Errorf("disclosure has %d elements", len(fields))
		}
		hasher.Reset()
		hasher.Write([]byte(d))
		sd.byDigest[base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))] = disc
		sd.disclosures = append(sd.disclosures, d)
	}
	return sd, nil
}

// claimMatch is one value a claims path pointer reached, and the
// disclosures that have to be presented for it to be visible.
type claimMatch struct {
	value any
	need  []string
}

// resolve walks a claims path pointer (OpenID4VP §7) through the payload,
// following _sd digests and array-element disclosures.
func (sd *sdJWT) resolve(node any, path []*string, need []string) []claimMatch {
	if len(path) == 0 {
		return []claimMatch{{value: node, need: append(slices.Clone(need), sd.nested(node)...)}}
	}

	switch n := node.(type) {
	case map[string]any:
		if path[0] == nil {
			return nil
		}
		key := *path[0]
		if child, ok := n[key]; ok && key != "_sd" {
			return sd.resolve(child, path[1:], need)
		}
		digests, _ := n["_sd"].([]any)
		for _, digest := range digests {
			s, _ := digest.(string)
			if disc, ok := sd.byDigest[s]; ok && disc.name == key {
				return sd.resolve(disc.value, path[1:], append(slices.Clone(need), disc.raw))
			}
		}
		return nil
	case []any:
		if path[0] != nil {
			return nil
		}
		var matches []claimMatch
		for _, element := range n {
			child, elementNeed := element, need
			if disc, ok := sd.arrayElement(element); ok {
				child, elementNeed = disc.value, append(slices.Clone(need), disc.raw)
			} else if isArrayPlaceholder(element) {
				// An undisclosed element or a decoy: there is no value to match.
				continue
			}
			matches = append(matches, sd.resolve(child, path[1:], elementNeed)...)
		}
		return matches
	default:
		return nil
	}
}

// nested is every disclosure reachable inside a selected value, since
// selecting a claim selects all of it.
func (sd *sdJWT) nested(node any) []string {
	var out []string
	switch n := node.(type) {
	case map[string]any:
		digests, _ := n["_sd"].([]any)
		for _, digest := range digests {
			s, _ := digest.(string)
			if disc, ok := sd.byDigest[s]; ok {
				out = append(out, disc.raw)
				out = append(out, sd.nested(disc.value)...)
			}
		}
		for k, v := range n {
			if k != "_sd" {
				out = append(out, sd.nested(v)...)
			}
		}
	case []any:
		for _, element := range n {
			if disc, ok := sd.arrayElement(element); ok {
				out = append(out, disc.raw)
				out = append(out, sd.nested(disc.value)...)
				continue
			}
			out = append(out, sd.nested(element)...)
		}
	}
	return out
}

// isArrayPlaceholder reports whether element is a {"...": digest} array
// element marker (SD-JWT §4.2.4.2), disclosed or not.
func isArrayPlaceholder(element any) bool {
	m, ok := element.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	_, ok = m["..."].(string)
	return ok
}

func (sd *sdJWT) arrayElement(element any) (sdDisclosure, bool) {
	m, ok := element.(map[string]any)
	if !ok || len(m) != 1 {
		return sdDisclosure{}, false
	}
	digest, _ := m["..."].(string)
	disc, ok := sd.byDigest[digest]
	return disc, ok
}

// claimDisclosures answers one claim query: whether the claim exists with
// an acceptable value, and which disclosures reveal it.
func (sd *sdJWT) claimDisclosures(query openid4vp.ClaimQuery) ([]string, bool) {
	var need []string
	found := false
	for _, m := range sd.resolve(sd.payload, query.Path, nil) {
		if len(query.Values) > 0 && !slices.ContainsFunc(query.Values, func(v any) bool { return claimValueEqual(m.value, v) }) {
			continue
		}
		found = true
		need = append(need, m.need...)
	}
	return need, found
}

// claimValueEqual is the exact type-and-value match of OpenID4VP §6.4.1.
// Both sides come from JSON, so numbers are compared as float64.
func claimValueEqual(claim, want any) bool {
	switch w := want.(type) {
	case string:
		c, ok := claim.(string)
		return ok && c == w
	case bool:
		c, ok := claim.(bool)
		return ok && c == w
	}
	cf, cok := asFloat(claim)
	wf, wok := asFloat(want)
	return cok && wok && cf == wf
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// selectClaims applies a credential query's claims and claim_sets to an
// SD-JWT credential and returns the presentation carrying only the
// disclosures those claims need. ok is false when the credential cannot
// satisfy the claim constraints, or is not an SD-JWT this wallet can
// reduce.
func selectClaims(raw string, query openid4vp.CredentialQuery) (string, bool) {
	sd, err := parseSDJWT(raw)
	if err != nil {
		return "", false
	}

	answered := map[string][]string{}
	for i, claim := range query.Claims {
		if need, ok := sd.claimDisclosures(claim); ok {
			answered[claimQueryKey(claim, i)] = need
		}
	}

	var chosen []string
	if len(query.ClaimSet) == 0 {
		for i, claim := range query.Claims {
			need, ok := answered[claimQueryKey(claim, i)]
			if !ok {
				return "", false
			}
			chosen = append(chosen, need...)
		}
	} else {
		// §6.4.1: the first claim set the credential satisfies, in the
		// Verifier's order of preference.
		satisfied := false
		for _, set := range query.ClaimSet {
			var need []string
			all := true
			for _, id := range set {
				n, ok := answered[id]
				if !ok {
					all = false
					break
				}
				need = append(need, n...)
			}
			if all {
				chosen, satisfied = need, true
				break
			}
		}
		if !satisfied {
			return "", false
		}
	}

	var b strings.Builder
	b.WriteString(sd.issuerJWT)
	b.WriteByte('~')
	for _, d := range sd.disclosures {
		if slices.Contains(chosen, d) {
			b.WriteString(d)
			b.WriteByte('~')
		}
	}
	return b.String(), true
}

// claimQueryKey is how claim_sets reference a claim query: by its id.
// A query without claim_sets may omit ids, so its position stands in.
func claimQueryKey(claim openid4vp.ClaimQuery, index int) string {
	if claim.ID != "" {
		return claim.ID
	}
	return fmt.Sprintf("#%d", index)
}
