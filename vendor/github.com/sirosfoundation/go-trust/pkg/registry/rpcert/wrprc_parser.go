// WRPRC payload parsing per ETSI TS 119 475, tolerant of both v1.1.1 and
// v1.2.1 field spellings.
//
// Validating a signed object is three steps: verify the signature, extract
// the trust information, evaluate it. This file is step two and only step
// two. It decodes payload bytes into RPEntitlements and does not verify a
// signature, build a certificate chain, consult a clock, or reach the
// network. Callers own steps one and three - see ParseWRPRCClaims.
//
// The tolerance here is not hypothetical. The wire shapes below were taken
// from a certificate issued by the German EUDI sandbox Registrar, which
// differs from a strict reading of the v1.1.1 tables in four ways at once.

package rpcert

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ParseWRPRCClaims decodes a WRPRC JWT payload into RPEntitlements.
//
// payload is the decoded JWT payload - the middle segment of the compact
// JWT, already base64url-decoded. Use ParseWRPRCJWTPayload to get those
// bytes from a compact token.
//
// It performs no cryptographic verification of any kind. A successful return
// means the bytes were a well-formed WRPRC payload, nothing more: the caller
// must already have verified the signature (step one) and must still
// evaluate the issuing chain against its trust anchors (step three) before
// treating anything here as trustworthy. Accordingly the returned
// RegistrationStatus is StatusUnknown, so RPEntitlements.IsValid reports
// false until a caller that has completed step three says otherwise.
//
// Both TS 119 475 v1.1.1 and v1.2.1 spellings are accepted, so one
// implementation serves Registrars that have migrated and those that have
// not:
//
//   - sub as a bare identifier string, or as the structured object
//   - the legal name in sub_ln, or nested in sub.legal_name
//   - the DCQL claim list named claim, or claims
//   - provided attestations under provides_attestations, or
//     provided_attestations
//   - service descriptions under srv_description, or service, either as a
//     flat list of localised strings or as a list of such lists
//
// Two structural requirements are enforced, because a document missing
// either is not a WRPRC rather than being a WRPRC we happen to dislike: a
// usable sub claim, and a non-empty entitlements claim (GEN-5.2.4-03).
// Time-based conformance is deliberately left out - see
// CheckWRPRCValidityPeriod.
func ParseWRPRCClaims(payload []byte) (*RPEntitlements, error) {
	var p wrprcPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("wrprc: parsing payload: %w", err)
	}

	if p.Sub.ID == "" && p.Sub.LegalName == "" && p.SubLegalName == "" &&
		p.Sub.GivenName == "" && p.Sub.FamilyName == "" && p.SubGivenName == "" && p.SubFamilyName == "" {
		return nil, fmt.Errorf("wrprc: payload has no usable sub claim")
	}
	if len(p.Entitlements) == 0 {
		return nil, fmt.Errorf("wrprc: payload has no entitlements claim (GEN-5.2.4-03)")
	}

	ent := &RPEntitlements{
		Subject: WRPRCSubject{
			ID:         p.Sub.ID,
			LegalName:  firstNonEmpty(p.SubLegalName, p.Sub.LegalName),
			GivenName:  firstNonEmpty(p.SubGivenName, p.Sub.GivenName),
			FamilyName: firstNonEmpty(p.SubFamilyName, p.Sub.FamilyName),
		},
		TradeName:         p.Name,
		Country:           p.Country,
		EntitlementURIs:   p.Entitlements,
		PrivacyPolicyURI:  p.PrivacyPolicy,
		InfoURI:           p.InfoURI,
		RegistryURI:       p.RegistryURI,
		PolicyIDs:         p.PolicyIDs,
		Purpose:           p.Purpose,
		IsPublicBody:      p.PublicBody,
		SupportURI:        p.SupportURI,
		ServiceIdentifier: p.ServiceIdentifier,
		// Parsing establishes nothing about registration - only a verified
		// signature and an evaluated chain can. Left for the caller to set.
		RegistrationStatus: StatusUnknown,
	}

	ent.ServiceDescriptions = firstNonEmptyText(p.ServiceDescription, p.Service)

	// The identifier is what binds this document to an access certificate
	// (ARF RPRC_16), so prefer the real identifier and only fall back to
	// names when the Registrar supplied none.
	ent.RPIdentifier = firstNonEmpty(
		ent.Subject.ID,
		ent.Subject.LegalName,
		strings.TrimSpace(ent.Subject.GivenName+" "+ent.Subject.FamilyName),
	)

	if p.Iat > 0 {
		t := time.Unix(p.Iat, 0)
		ent.ValidFrom = &t
	}
	if p.Exp > 0 {
		t := time.Unix(p.Exp, 0)
		ent.ValidUntil = &t
	}

	// act.sub names the intermediary presenting on the RP's behalf; sub
	// always names the final RP (GEN-5.2.4-09, Table 10).
	if p.Act != nil {
		ent.ActingIntermediary = p.Act.Sub
	}

	if p.Status != nil {
		ent.StatusListURI = p.Status.StatusList.URI
		ent.StatusListIndex = p.Status.StatusList.Idx
	}

	ent.AllowedAttributes = topLevelClaimNames(p.Credentials)
	ent.ProvidedAttestations = credentialQueries(firstNonEmptyCreds(p.ProvidesAttestations, p.ProvidedAttestations))

	return ent, nil
}

// ParseWRPRCJWTPayload returns the decoded payload segment of a compact JWT.
//
// This splits and base64url-decodes. It does NOT verify the signature, and
// callers must not treat a successful return as evidence of anything: the
// signature segment is not even examined. It exists so that every caller
// does not reimplement the same segment handling, which is where
// off-by-one and padding bugs live.
func ParseWRPRCJWTPayload(token string) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("wrprc: invalid compact JWT: expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("wrprc: decoding JWT payload segment: %w", err)
	}
	return payload, nil
}

// wrprcPayload mirrors the WRPRC wire format across TS 119 475 v1.1.1 and
// v1.2.1, holding both spellings of every field that moved so the reducer
// above can pick whichever the Registrar sent.
type wrprcPayload struct {
	Name string `json:"name"`

	// sub is an object in v1.1.1 and an identifier string in v1.2.1, with
	// the name parts promoted to siblings. wrprcSub accepts either shape.
	Sub           wrprcSub `json:"sub"`
	SubLegalName  string   `json:"sub_ln,omitempty"`
	SubGivenName  string   `json:"sub_gn,omitempty"`
	SubFamilyName string   `json:"sub_fn,omitempty"`

	// service_identifier is not in TS 119 475 yet; it is the de-facto claim
	// paired with the WRPAC subject attribute checked by
	// CheckWRPACWRPRCServiceBinding, which had nothing populating it before.
	ServiceIdentifier string `json:"service_identifier,omitempty"`

	Country       string   `json:"country"`
	Entitlements  []string `json:"entitlements"`
	PrivacyPolicy string   `json:"privacy_policy"`
	InfoURI       string   `json:"info_uri"`
	RegistryURI   string   `json:"registry_uri"`
	SupportURI    string   `json:"support_uri,omitempty"`
	PolicyIDs     []string `json:"policy_id,omitempty"`
	PublicBody    bool     `json:"public_body,omitempty"`
	Iat           int64    `json:"iat"`
	Exp           int64    `json:"exp"`

	Purpose []MultiLangString `json:"purpose,omitempty"`

	// service (v1.1.1) was renamed srv_description (v1.2.1).
	Service            localizedTexts `json:"service,omitempty"`
	ServiceDescription localizedTexts `json:"srv_description,omitempty"`

	Credentials []wrprcCredential `json:"credentials,omitempty"`

	// provided_attestations (v1.1.1) was renamed provides_attestations
	// (v1.2.1). Table 8, GEN-5.2.4-05.
	ProvidedAttestations []wrprcCredential `json:"provided_attestations,omitempty"`
	ProvidesAttestations []wrprcCredential `json:"provides_attestations,omitempty"`

	Status *wrprcStatus `json:"status,omitempty"`
	Act    *wrprcAct    `json:"act,omitempty"`
}

// wrprcSub is the sub claim in either of the two shapes Registrars emit.
// The tags are for marshalling only - UnmarshalJSON below overrides
// decoding entirely - but without them a round-trip through encoding/json
// silently loses every field whose name contains an underscore.
type wrprcSub struct {
	ID         string `json:"id,omitempty"`
	LegalName  string `json:"legal_name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
}

// UnmarshalJSON accepts both "sub": "NTRDE-BD7070256AF93987" and
// "sub": {"id": "...", "legal_name": "..."}.
//
// Rejecting the string form is not a harmless strictness: the German
// sandbox emits it, so a parser that insists on the object shape fails
// outright on a real Registrar's certificate.
func (s *wrprcSub) UnmarshalJSON(data []byte) error {
	var asString string
	if err := json.Unmarshal(data, &asString); err == nil {
		s.ID = asString
		return nil
	}
	var asObject struct {
		ID         string `json:"id"`
		LegalName  string `json:"legal_name"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	}
	if err := json.Unmarshal(data, &asObject); err != nil {
		return fmt.Errorf("sub claim is neither an identifier string nor an object: %w", err)
	}
	s.ID = asObject.ID
	s.LegalName = asObject.LegalName
	s.GivenName = asObject.GivenName
	s.FamilyName = asObject.FamilyName
	return nil
}

// wrprcCredential is one DCQL credential query.
//
// The claim list appears as both claim and claims in practice. Tolerating
// only one spelling does not fail loudly - it yields an empty attribute
// set, which reads downstream as "this RP may request nothing" and makes
// over-request detection silently inert.
type wrprcCredential struct {
	ID     string         `json:"id,omitempty"`
	Format string         `json:"format"`
	Meta   map[string]any `json:"meta,omitempty"`
	Claim  []wrprcClaim   `json:"claim,omitempty"`
	Claims []wrprcClaim   `json:"claims,omitempty"`
}

// entries returns whichever spelling of the claim list this query used.
func (c wrprcCredential) entries() []wrprcClaim {
	if len(c.Claim) > 0 {
		return c.Claim
	}
	return c.Claims
}

type wrprcClaim struct {
	ID   string   `json:"id,omitempty"`
	Path []string `json:"path"`
}

// wrprcStatus holds the status claim carrying the Token Status List
// reference used for WRPRC revocation (Table 7).
type wrprcStatus struct {
	StatusList struct {
		Idx int    `json:"idx"`
		URI string `json:"uri"`
	} `json:"status_list"`
}

// wrprcAct holds the act claim identifying an intermediary
// (Table 10, GEN-5.2.4-09).
type wrprcAct struct {
	Sub string `json:"sub"`
}

// localizedTexts is a list of localised strings that tolerates the extra
// level of nesting Registrars emit.
//
// TS 119 475 describes a list of MultiLangString, but the German sandbox
// sends srv_description as a list of such lists - [[{lang,value}]] rather
// than [{lang,value}]. Both decode to the same flattened result here.
type localizedTexts []MultiLangString

func (l *localizedTexts) UnmarshalJSON(data []byte) error {
	var flat []MultiLangString
	if err := json.Unmarshal(data, &flat); err == nil {
		*l = flat
		return nil
	}
	var nested [][]MultiLangString
	if err := json.Unmarshal(data, &nested); err != nil {
		return fmt.Errorf("localised text is neither a list nor a list of lists: %w", err)
	}
	var out []MultiLangString
	for _, group := range nested {
		out = append(out, group...)
	}
	*l = out
	return nil
}

// topLevelClaimNames flattens the DCQL credential queries to the unique
// top-level claim names the RP is registered to request (Table 9).
//
// Only path[0] is taken: entitlement checks operate at the attribute level,
// so a nested path like ["address", "locality"] contributes "address".
func topLevelClaimNames(creds []wrprcCredential) []string {
	seen := map[string]bool{}
	var attrs []string
	for _, cred := range creds {
		for _, claim := range cred.entries() {
			if len(claim.Path) == 0 || claim.Path[0] == "" || seen[claim.Path[0]] {
				continue
			}
			seen[claim.Path[0]] = true
			attrs = append(attrs, claim.Path[0])
		}
	}
	return attrs
}

// credentialQueries converts wire credential queries to the exported shape.
func credentialQueries(creds []wrprcCredential) []CredentialQuery {
	var out []CredentialQuery
	for _, c := range creds {
		cq := CredentialQuery{ID: c.ID, Format: c.Format, Meta: c.Meta}
		for _, claim := range c.entries() {
			cq.Claims = append(cq.Claims, ClaimQuery{ID: claim.ID, Path: claim.Path})
		}
		out = append(out, cq)
	}
	return out
}

// firstNonEmpty returns the first non-empty string, or "".
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// firstNonEmptyText returns the first non-empty localised-text list.
func firstNonEmptyText(lists ...localizedTexts) []MultiLangString {
	for _, l := range lists {
		if len(l) > 0 {
			return l
		}
	}
	return nil
}

// firstNonEmptyCreds returns the first non-empty credential-query list.
func firstNonEmptyCreds(lists ...[]wrprcCredential) []wrprcCredential {
	for _, l := range lists {
		if len(l) > 0 {
			return l
		}
	}
	return nil
}
