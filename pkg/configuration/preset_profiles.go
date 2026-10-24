package configuration

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// checkPresetValidationProfiles applies each preset credential's opt-in
// `validate:` profile, at startup.
//
// Startup is the only place this runs. The browser builds the DCQL query
// and posts it back with no preset identity attached, so by the time a
// request arrives there is nothing left to say which profile - if any -
// its author had in mind; and judging live traffic against a rulebook is
// not this verifier's job anyway, since sending a deliberately
// non-conformant request is how a wallet gets tested. An operator who
// wants to be told their preset violates the nym_auth rulebook asks by
// name, and is told while they are still editing configuration.
//
// Opt-in, so a config that names no profile is unaffected.
func checkPresetValidationProfiles(cfg *model.Cfg) error {
	if cfg == nil || cfg.Verifier == nil {
		return nil
	}
	var problems []string
	for _, label := range slices.Sorted(maps.Keys(cfg.Verifier.Presets)) {
		preset := cfg.Verifier.Presets[label]
		for _, scope := range slices.Sorted(maps.Keys(preset.Credentials)) {
			scopeCfg := preset.Credentials[scope]
			if scopeCfg == nil || scopeCfg.Validate == "" {
				continue
			}
			query := presetQuery(cfg, scope, scopeCfg)
			if err := openid4vp.ValidateProfile(scopeCfg.Validate, query); err != nil {
				problems = append(problems, fmt.Sprintf(
					"verifier.presets.%q.credentials.%q (validate: %s): %v", label, scope, scopeCfg.Validate, err))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("preset validation profile failed:\n\t%s", strings.Join(problems, "\n\t"))
	}
	return nil
}

// presetQuery reconstructs the credential query a preset would produce,
// the same way internal/verifier/apiv1 builds it for the UI: the scope's
// own credential_metadata supplies format and meta, and the preset's
// overrides are applied on top.
//
// Built here rather than imported from that package because the check has
// to run before any service wiring exists - and because a check that
// judged something other than what the UI publishes would be worse than
// no check at all.
func presetQuery(cfg *model.Cfg, scope string, scopeCfg *model.VerificationPresetScope) openid4vp.CredentialQuery {
	query := openid4vp.CredentialQuery{ID: scope, Req: scopeCfg.Req}
	if cfg.Common != nil {
		if meta := cfg.Common.CredentialMetadata[scope]; meta != nil {
			query.Format = meta.Format
			if mq, ok := meta.DCQLMetaQuery(); ok {
				query.Meta = mq
			}
		}
	}
	if scopeCfg.Format != "" {
		query.Format = scopeCfg.Format
	}
	// Mirrors the derivation in internal/verifier/apiv1: a zkp_req
	// request carries the scope's own stored format as
	// meta.source_format, and is unanswerable without it. Judging a
	// query that lacked it would be judging a request the UI never
	// publishes.
	if openid4vp.IsZkpReqFormat(query.Format) && cfg.Common != nil {
		if meta := cfg.Common.CredentialMetadata[scope]; meta != nil {
			query.Meta.SourceFormat = meta.Format
		}
	}
	if len(scopeCfg.ZKSystemType) > 0 {
		query.Meta.ZKSystemType = scopeCfg.ZKSystemType
	}
	// The UI drops a circuit_zk scope's claims entirely, so judging them
	// here would report a conflict the wire never carries. Everything
	// else keeps them, because for those formats the claims ARE the query.
	if !openid4vp.IsZkpReqFormat(query.Format) {
		for _, claim := range scopeCfg.Claims {
			query.Claims = append(query.Claims, openid4vp.ClaimQuery{Path: stringPathToPtrPath(claim.Path)})
		}
	}
	return query
}

func stringPathToPtrPath(path []string) []*string {
	out := make([]*string, len(path))
	for i := range path {
		out[i] = &path[i]
	}
	return out
}

// checkZkpReqPresetsAskForSomething refuses a zkp_req preset whose `req`
// is empty, at startup, whether or not the preset opted into a profile.
//
// Unconditional because of how the key is spelled. v0.4 renamed the WIRE
// member from `req` to `_req`; the preset key - this repository's own
// configuration surface - stayed `req`. An operator reading the rulebook
// writes `_req`, and configuration is deliberately NOT loaded with
// UnmarshalStrict, so nothing says a word: the preset simply has no
// items, the request asks the wallet for nothing, and the wallet answers
// with nothing. That failure reads as the wallet's.
//
// The rule itself is the matcher's (req_missing_or_empty): a zkp_req
// query with no items is refused there too. This only says it at the
// point where it is still a configuration mistake.
func checkZkpReqPresetsAskForSomething(cfg *model.Cfg) error {
	if cfg == nil || cfg.Verifier == nil {
		return nil
	}
	var problems []string
	for _, label := range slices.Sorted(maps.Keys(cfg.Verifier.Presets)) {
		preset := cfg.Verifier.Presets[label]
		for _, scope := range slices.Sorted(maps.Keys(preset.Credentials)) {
			scopeCfg := preset.Credentials[scope]
			if scopeCfg == nil || !openid4vp.IsZkpReqFormat(scopeCfg.Format) || len(scopeCfg.Req) > 0 {
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"verifier.presets.%q.credentials.%q asks for format %s but its req is empty, so the request would ask the wallet for nothing; the preset key is `req` (the wire member it becomes is `_req`)",
				label, scope, openid4vp.FormatZkpReq))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("zkp_req preset asks for nothing:\n\t%s", strings.Join(problems, "\n\t"))
	}
	return nil
}
