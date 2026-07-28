// Package rpcert — DCQL policy evaluator interface and built-in implementations.
//
// DCQLPolicyEvaluator checks whether a credential request (DCQL query) is within
// the scope authorised by the RP's WRPRC entitlements. The evaluation is invoked
// after WRPRC signature verification, before the wallet discloses attributes.
//
// The interface is designed for injection: callers that need EDP (Electronic Data
// Policy) enforcement inject their own implementation; those that only need
// entitlement-level enforcement use StrictDCQLPolicyEvaluator; those that want
// audit-only warnings use PermissiveDCQLPolicyEvaluator.
//
// User-override prompts (RFC003 AUTHZ-EDPV-01-OVERRIDE, AUTHZ-EDPV-02-OVERRIDE)
// are NOT in this package — they are a UI/UX concern that belongs in the wallet
// frontend. This package returns typed errors; the caller decides what to present.
//
// References:
//   - ETSI TS 119 475 v1.1.1 Tables 8–9 — WRPRC credential queries
//   - RFC003 §10.2.3 AUTHZ-ENT-*, AUTHZ-EDPV-*
package rpcert

import (
	"context"
	"fmt"
	"strings"
)

// DCQLPolicyResult is returned by DCQLPolicyEvaluator.Evaluate.
type DCQLPolicyResult struct {
	// Allowed indicates whether the request may proceed.
	Allowed bool

	// OverRequestedTypes lists credential types/formats present in the request
	// but absent from the RP's registered credentials array. Empty when Allowed=true.
	OverRequestedTypes []string

	// Message is a human-readable description of the outcome, suitable for
	// inclusion in audit logs or deny-reason fields.
	Message string
}

// DCQLPolicyEvaluator checks whether a DCQL credential request is authorised
// by the RP's WRPRC entitlements.
type DCQLPolicyEvaluator interface {
	// Evaluate checks the request against the entitlements. requestedTypes is
	// the list of credential types (vct values or ISO mdoc doctypes) being
	// requested. Returns a DCQLPolicyResult; never returns a Go error — policy
	// outcomes are communicated through the result struct.
	Evaluate(ctx context.Context, ent *RPEntitlements, requestedTypes []string) DCQLPolicyResult
}

// StrictDCQLPolicyEvaluator denies requests containing credential types not
// listed in the RP's registered credentials array. Use this for production
// deployments where over-requesting must be blocked at the trust layer.
type StrictDCQLPolicyEvaluator struct{}

// Evaluate returns Allowed=false when any requested type is absent from the
// credential types registered in the RP's entitlements.
//
// requestedTypes should be credential type identifiers such as:
//   - SD-JWT VC vct values: "eu.europa.ec.eudi.pid.1"
//   - ISO mdoc doctypes: "org.iso.18013.5.1.mDL"
//
// The allow-list is built from ProvidedAttestations (for EAA providers) and
// the credentials array (for relying-party flows), by extracting vct/doctype
// values from the credential meta fields. Format strings (e.g. "sd-jwt") and
// claim attribute names (e.g. "family_name") are distinct and are not matched
// here — use DetectOverRequest for attribute-level enforcement.
func (StrictDCQLPolicyEvaluator) Evaluate(_ context.Context, ent *RPEntitlements, requestedTypes []string) DCQLPolicyResult {
	if ent == nil || len(requestedTypes) == 0 {
		return DCQLPolicyResult{Allowed: true, Message: "no credential types to check"}
	}

	// Build the allow-set from registered credential type identifiers.
	// We extract vct (SD-JWT VC) and doctype (mdoc) values from the meta fields
	// of ProvidedAttestations entries. Format strings (sd-jwt, mso_mdoc) are
	// added as a coarse-grained fallback for entries that lack a type meta field.
	allowed := make(map[string]bool)
	for _, c := range ent.ProvidedAttestations {
		if vct, ok := c.Meta["vct"].(string); ok && vct != "" {
			allowed[strings.ToLower(vct)] = true
		}
		if dt, ok := c.Meta["doctype"].(string); ok && dt != "" {
			allowed[strings.ToLower(dt)] = true
		}
		// vct_values is an array form used in some DCQL profiles
		if vctVals, ok := c.Meta["vct_values"].([]interface{}); ok {
			for _, v := range vctVals {
				if s, ok := v.(string); ok && s != "" {
					allowed[strings.ToLower(s)] = true
				}
			}
		}
		if c.Format != "" {
			allowed[strings.ToLower(c.Format)] = true
		}
	}

	if len(allowed) == 0 {
		// No registered credential type data — cannot enforce; permit.
		return DCQLPolicyResult{Allowed: true, Message: "no registered credential types; cannot enforce DCQL policy"}
	}

	var over []string
	for _, t := range requestedTypes {
		if !allowed[strings.ToLower(t)] {
			over = append(over, t)
		}
	}
	if len(over) == 0 {
		return DCQLPolicyResult{Allowed: true, Message: "all requested types are within entitlements"}
	}
	return DCQLPolicyResult{
		Allowed:            false,
		OverRequestedTypes: over,
		Message: fmt.Sprintf("RP %q is requesting credential types not in entitlements: %s (AUTHZ-ATT-01-FAIL)",
			ent.RPIdentifier, strings.Join(over, ", ")),
	}
}

// PermissiveDCQLPolicyEvaluator always permits the request but populates
// OverRequestedTypes for audit. Use this in warn-only deployments where the
// wallet wants to log over-requests without blocking the flow.
type PermissiveDCQLPolicyEvaluator struct{}

// Evaluate always returns Allowed=true but notes any over-requested types.
func (PermissiveDCQLPolicyEvaluator) Evaluate(ctx context.Context, ent *RPEntitlements, requestedTypes []string) DCQLPolicyResult {
	strict := StrictDCQLPolicyEvaluator{}
	r := strict.Evaluate(ctx, ent, requestedTypes)
	r.Allowed = true // override — permissive mode never blocks
	if len(r.OverRequestedTypes) > 0 {
		r.Message = fmt.Sprintf("WARN: over-requested types (not blocking): %s", strings.Join(r.OverRequestedTypes, ", "))
	}
	return r
}
