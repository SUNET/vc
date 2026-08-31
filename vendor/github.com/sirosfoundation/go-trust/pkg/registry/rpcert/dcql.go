// DCQL (Digital Credentials Query Language) types for over-request detection.
//
// A DCQL query specifies which credentials and claims an RP is requesting from
// the wallet. Over-request detection compares the requested claims against the
// RP's entitled attributes.
//
// References:
//   - OpenID4VP DCQL specification
//   - ETSI TS 119 475 v1.1.1 — RP attributes supporting Wallet user's authorisation decisions

package rpcert

// DCQLQuery represents a DCQL query as defined in OpenID4VP.
// It specifies which credentials (and their claims) the RP is requesting.
type DCQLQuery struct {
	Credentials []CredentialQuery `json:"credentials"`
}

// CredentialQuery represents a single credential request within a DCQL query.
type CredentialQuery struct {
	// ID is an identifier for this credential query.
	ID string `json:"id"`

	// Format specifies the credential format (e.g., "vc+sd-jwt", "mso_mdoc").
	Format string `json:"format"`

	// Meta contains format-specific metadata (e.g., vct_values for SD-JWT).
	Meta map[string]interface{} `json:"meta,omitempty"`

	// Claims lists the claims being requested from this credential.
	Claims []ClaimQuery `json:"claims,omitempty"`

	// ClaimSets groups alternative sets of claims (any one set suffices).
	ClaimSets [][]string `json:"claim_sets,omitempty"`
}

// ClaimQuery represents a single claim request within a credential query.
type ClaimQuery struct {
	// ID is an optional identifier for this claim query.
	ID string `json:"id,omitempty"`

	// Path is the claim path within the credential (e.g., ["family_name"] or
	// ["address", "street_address"] for nested claims).
	Path []string `json:"path"`

	// Values constrains the acceptable values for this claim.
	Values interface{} `json:"values,omitempty"`
}

// ExtractRequestedClaimNames returns a flat list of top-level claim names
// from a DCQL query. For nested paths like ["address", "street_address"],
// only the top-level name "address" is returned since entitlement checks
// operate at the attribute level.
func (q *DCQLQuery) ExtractRequestedClaimNames() []string {
	if q == nil {
		return nil
	}
	seen := make(map[string]bool)
	var names []string
	for _, cred := range q.Credentials {
		for _, claim := range cred.Claims {
			if len(claim.Path) > 0 {
				name := claim.Path[0]
				if !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}
	return names
}

// ParseDCQLQuery parses a DCQL query from a generic map[string]interface{}
// (as received from JSON deserialization in request context or action parameters).
func ParseDCQLQuery(raw interface{}) *DCQLQuery {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}

	query := &DCQLQuery{}

	credsRaw, ok := m["credentials"]
	if !ok {
		return query
	}

	credsList, ok := credsRaw.([]interface{})
	if !ok {
		return query
	}

	for _, credRaw := range credsList {
		credMap, ok := credRaw.(map[string]interface{})
		if !ok {
			continue
		}

		cq := CredentialQuery{}
		if id, ok := credMap["id"].(string); ok {
			cq.ID = id
		}
		if format, ok := credMap["format"].(string); ok {
			cq.Format = format
		}
		if meta, ok := credMap["meta"].(map[string]interface{}); ok {
			cq.Meta = meta
		}

		if claimsRaw, ok := credMap["claims"].([]interface{}); ok {
			for _, claimRaw := range claimsRaw {
				claimMap, ok := claimRaw.(map[string]interface{})
				if !ok {
					continue
				}
				claim := ClaimQuery{}
				if id, ok := claimMap["id"].(string); ok {
					claim.ID = id
				}
				if pathRaw, ok := claimMap["path"].([]interface{}); ok {
					for _, p := range pathRaw {
						if s, ok := p.(string); ok {
							claim.Path = append(claim.Path, s)
						}
					}
				}
				claim.Values = claimMap["values"]
				cq.Claims = append(cq.Claims, claim)
			}
		}

		query.Credentials = append(query.Credentials, cq)
	}

	return query
}
