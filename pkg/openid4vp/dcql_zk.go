package openid4vp

import (
	"encoding/json"
	"fmt"
)

// This file adds DCQL support for the "mso_mdoc_zk" credential format —
// zero-knowledge (Longfellow) proof-of-possession presentations of an mdoc,
// optionally including a pairwise pseudonym (PPID), as produced by
// multipaz-compatible wallets (and this org's own siros-sdk-kotlin/swift).
//
// It is intentionally additive: FormatMsoMdocZk/ZKSystemTypeSpec are new
// types, and MetaQuery gains two new omitempty fields. Nothing here changes
// existing "mso_mdoc" (non-ZK) request/response handling.
//
// See docs/ZK_PPID_VERIFICATION_PLAN.md for the full design writeup,
// including exactly how far verification (pkg/mdoc/zk*.go) gets today and
// what native-binding work remains.

// FormatMsoMdocZk is the DCQL/OpenID4VP format identifier for a
// zero-knowledge-proof presentation of an ISO mdoc credential (multipaz's
// "mso_mdoc_zk", as opposed to the plain "mso_mdoc" format). A wallet
// presenting this format returns a DeviceResponse-shaped `vp_token` whose
// top-level CBOR map has a `zkDocuments` array instead of (or alongside) the
// standard `documents` array — see pkg/mdoc.ZkDocumentMdoc.
const FormatMsoMdocZk = "mso_mdoc_zk"

// IsMdocZkFormat returns true if format is the ZK-mdoc DCQL format
// identifier ("mso_mdoc_zk").
func IsMdocZkFormat(format string) bool {
	return format == FormatMsoMdocZk
}

// ZKSystemTypeSpec is one entry of a CredentialQuery's `meta.zk_system_type`
// array — a verifier's declaration of one ZK proof system + circuit variant
// it is willing to accept, mirroring multipaz's `ZkSystemSpec` wire shape
// (`{"id": ..., "system": ..., ...params}`, e.g.
// `{"id": "longfellow-libzk-v1_8_1_4259_2945", "system": "longfellow-libzk-v1",
// "num_attributes": 1, "circuit_hash": "...", "block_enc_hash": ...,
// "block_enc_sig": ...}`).
//
// Params is a flat string->string bag (all non-id/system JSON members of the
// wire object). Numeric wire values (e.g. num_attributes, block_enc_hash)
// are carried through as their JSON text representation - callers that need
// a specific field as an int/int64 should parse it themselves. This mirrors
// the DCQL CredentialQuery model overall: format-specific "meta" properties
// are intentionally loosely typed at this layer.
type ZKSystemTypeSpec struct {
	// ID identifies this specific system+circuit combination
	// (e.g. "longfellow-libzk-v1_8_1_4259_2945"). A presented ZK document's
	// own `zkSystemId` (pkg/mdoc.ZkDocumentDataMdoc.ZkSystemID) is expected
	// to equal one of a request's ZKSystemType[].ID entries - this is how a
	// verifier confirms the wallet actually used a circuit it offered,
	// rather than some other one.
	ID string `json:"id" yaml:"id" validate:"required"`

	// System is the ZK proof system identifier (e.g. "longfellow-libzk-v1").
	// Params other than "id"/"system" are format-specific (circuit_hash,
	// num_attributes, block_enc_hash, block_enc_sig for Longfellow).
	System string `json:"system" yaml:"system" validate:"required"`

	// Params holds every other member of the wire object, as strings.
	// The json:"-"/yaml:"-" tags exist only so the default struct-tag
	// reflection codecs never touch this field directly - MarshalJSON/
	// UnmarshalJSON and MarshalYAML/UnmarshalYAML below fully own how
	// Params is (de)serialized (flattened to the top level, not nested
	// under a "params" key/property).
	Params map[string]string `json:"-" yaml:"-"`
}

// GetParam returns a system-specific parameter by key, or "" if absent.
func (z ZKSystemTypeSpec) GetParam(key string) string {
	return z.Params[key]
}

// MarshalJSON implements custom JSON marshaling for ZKSystemTypeSpec.
// The wire format is a single flat object (`{"id":..,"system":..,<params>}`),
// not a nested "params" object, mirroring multipaz's own ZkSystemSpec JSON
// shape - so Params is flattened back to the top level here.
func (z ZKSystemTypeSpec) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(z.Params)+2)
	for k, v := range z.Params {
		m[k] = v
	}
	m["id"] = z.ID
	m["system"] = z.System
	return json.Marshal(m)
}

// UnmarshalJSON implements custom JSON unmarshaling for ZKSystemTypeSpec.
// Every member other than "id"/"system" is captured in Params. Non-string
// JSON values (numbers, booleans - e.g. `"num_attributes": 1`) are kept as
// their JSON text representation rather than rejected, since the wire
// format allows either.
func (z *ZKSystemTypeSpec) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	idRaw, ok := m["id"]
	if !ok {
		return fmt.Errorf("zk_system_type entry missing required \"id\"")
	}
	var id string
	if err := json.Unmarshal(idRaw, &id); err != nil {
		return fmt.Errorf("zk_system_type entry \"id\" must be a string: %w", err)
	}

	systemRaw, ok := m["system"]
	if !ok {
		return fmt.Errorf("zk_system_type entry missing required \"system\"")
	}
	var system string
	if err := json.Unmarshal(systemRaw, &system); err != nil {
		return fmt.Errorf("zk_system_type entry \"system\" must be a string: %w", err)
	}

	params := make(map[string]string, len(m))
	for k, raw := range m {
		if k == "id" || k == "system" {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			params[k] = s
		} else {
			params[k] = string(raw)
		}
	}

	z.ID = id
	z.System = system
	z.Params = params
	return nil
}

// MarshalYAML implements gopkg.in/yaml.v2's Marshaler interface for
// ZKSystemTypeSpec, mirroring MarshalJSON: the config shape is a single
// flat mapping (`id`, `system`, plus every Params entry), not a nested
// "params" key.
func (z ZKSystemTypeSpec) MarshalYAML() (any, error) {
	m := make(map[string]any, len(z.Params)+2)
	for k, v := range z.Params {
		m[k] = v
	}
	m["id"] = z.ID
	m["system"] = z.System
	return m, nil
}

// UnmarshalYAML implements gopkg.in/yaml.v2's Unmarshaler interface for
// ZKSystemTypeSpec, mirroring UnmarshalJSON: every mapping key other than
// "id"/"system" is captured in Params (as its string form). Without this,
// the Params field's json:"-"/yaml:"-" tags would make it impossible for
// a YAML-authored config (e.g. pkg/configuration's presentation request
// templates, loaded via gopkg.in/yaml.v2) to ever set
// num_attributes/circuit_hash/etc - only a JSON request body could,
// since MarshalJSON/UnmarshalJSON already handle that path.
func (z *ZKSystemTypeSpec) UnmarshalYAML(unmarshal func(any) error) error {
	var m map[string]any
	if err := unmarshal(&m); err != nil {
		return err
	}

	idRaw, ok := m["id"]
	if !ok {
		return fmt.Errorf("zk_system_type entry missing required \"id\"")
	}
	id, ok := idRaw.(string)
	if !ok {
		return fmt.Errorf("zk_system_type entry \"id\" must be a string")
	}

	systemRaw, ok := m["system"]
	if !ok {
		return fmt.Errorf("zk_system_type entry missing required \"system\"")
	}
	system, ok := systemRaw.(string)
	if !ok {
		return fmt.Errorf("zk_system_type entry \"system\" must be a string")
	}

	params := make(map[string]string, len(m))
	for k, v := range m {
		if k == "id" || k == "system" {
			continue
		}
		if s, ok := v.(string); ok {
			params[k] = s
		} else {
			params[k] = fmt.Sprintf("%v", v)
		}
	}

	z.ID = id
	z.System = system
	z.Params = params
	return nil
}

// MatchZKSystemType finds the requested ZKSystemTypeSpec whose ID matches
// presentedZkSystemID (the `zkSystemId` a wallet actually used, taken from
// the presented ZkDocumentData). Returns (spec, true) on a match.
//
// This matches by exact ID equality, which is what the DCQL/multipaz wire
// convention assumes (a wallet either uses the exact circuit variant a
// verifier offered, in which case it should echo that same ID back, or the
// presentation doesn't satisfy the request at all). A stricter/looser
// implementation could instead re-derive a match from System + individual
// params (circuit_hash, num_attributes) rather than trusting the ID string
// verbatim - useful if a wallet's own circuit catalog ever assigns different
// IDs than the verifier's for what is otherwise the same circuit. That is
// not implemented here; flagging it as a known simplification.
func MatchZKSystemType(requested []ZKSystemTypeSpec, presentedZkSystemID string) (*ZKSystemTypeSpec, bool) {
	for i := range requested {
		if requested[i].ID == presentedZkSystemID {
			return &requested[i], true
		}
	}
	return nil, false
}
