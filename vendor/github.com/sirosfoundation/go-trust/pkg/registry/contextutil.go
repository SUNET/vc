package registry

// ExtractStringList reads a string list from an AuthZEN request's context
// map. Values may arrive as []string (set directly, e.g. from Go code or
// tests) or []interface{} (typical after JSON unmarshaling). Registries use
// this to read policy-derived constraints (e.g. issuer or AAGUID allow/
// blocklists) that RegistryManager.applyPolicyToRequest placed in
// req.Context.
func ExtractStringList(ctx map[string]interface{}, key string) []string {
	v, ok := ctx[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}
