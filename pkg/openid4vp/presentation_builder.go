package openid4vp

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
)

// PresentationRequestTemplate represents a template for creating presentation requests.
// This is a minimal interface to avoid import cycles with pkg/configuration.
type PresentationRequestTemplate interface {
	GetID() string
	GetOIDCScopes() []string
	GetDCQLQuery() *DCQL
}

// PresentationBuilder builds OpenID4VP presentation requests from templates
type PresentationBuilder struct {
	templates  map[string]PresentationRequestTemplate // ID -> template
	scopeIndex map[string]string                      // scope -> template ID
}

// NewPresentationBuilder creates a new PresentationBuilder with the given templates
// The templates parameter accepts any slice of types that implement PresentationRequestTemplate
func NewPresentationBuilder[T PresentationRequestTemplate](templates []T) *PresentationBuilder {
	builder := &PresentationBuilder{
		templates:  make(map[string]PresentationRequestTemplate),
		scopeIndex: make(map[string]string),
	}

	// Index templates by ID and scopes
	for _, template := range templates {
		id := template.GetID()
		builder.templates[id] = template

		// Index by each scope
		for _, scope := range template.GetOIDCScopes() {
			builder.scopeIndex[scope] = id
		}
	}

	return builder
}

// BuildFromScopes creates a DCQL query from OIDC scopes using configured templates
// Returns the DCQL query and the template that was used
func (pb *PresentationBuilder) BuildFromScopes(ctx context.Context, scopes []string) (*DCQL, PresentationRequestTemplate, error) {
	if len(scopes) == 0 {
		return nil, nil, fmt.Errorf("no scopes provided")
	}

	// Through selectTemplate, like every other path: picking the first
	// matching scope instead meant "openid eduid" chose whichever template
	// "openid" indexes, while claim extraction chose eduid's - so the query
	// sent to the wallet and the mapping used to read the answer could come
	// from different templates. Selection has to be one deterministic
	// function of the request.
	template, ok := pb.selectTemplate(scopes)
	if !ok {
		return nil, nil, fmt.Errorf("no template found for scopes %v", scopes)
	}

	dcql := template.GetDCQLQuery()
	if dcql == nil {
		return nil, nil, fmt.Errorf("template %s has no DCQL query", template.GetID())
	}

	// A copy, for the reason TemplateDCQLQuery gives: a caller completing the
	// query in place must not edit the template every later request is built
	// from.
	return copyDCQL(dcql), template, nil
}

// BuildFromTemplate creates a DCQL query from a specific template ID
func (pb *PresentationBuilder) BuildFromTemplate(ctx context.Context, templateID string) (*DCQL, PresentationRequestTemplate, error) {
	template, ok := pb.templates[templateID]
	if !ok {
		return nil, nil, fmt.Errorf("template %s not found", templateID)
	}

	dcql := template.GetDCQLQuery()
	if dcql == nil {
		return nil, nil, fmt.Errorf("template %s has no DCQL query", template.GetID())
	}

	return dcql, template, nil
}

// BuildDCQLQuery creates a DCQL query from OIDC scopes.
// This attempts to find matching templates, and falls back to a generic DCQL query if none are found.
//
// A caller with a better fallback than the generic query - building from
// credential_metadata, say - wants TemplateDCQLQuery instead, which reports the
// no-match case instead of standing in for it.
func (pb *PresentationBuilder) BuildDCQLQuery(ctx context.Context, scopes []string) (*DCQL, error) {
	if dcql, _, matched := pb.TemplateDCQLQuery(ctx, scopes); matched {
		return dcql, nil
	}
	return pb.createGenericDCQL(), nil
}

// TemplateDCQLQuery returns a copy of the DCQL query of the template matching
// scopes, and whether one matched at all. All scopes are considered, including
// standard OIDC scopes like "openid", so a standard scope can map to a
// credential when configured; non-standard scopes are tried first so "openid"
// does not win merely by appearing first in the request.
//
// The template's declared oidc_scopes come back alongside the query.
//
// matched is what BuildDCQLQuery cannot express: it answers "no template" with
// a generic placeholder that constrains nothing and reads like success, and
// that case cannot be inferred back out of the query since credential ids are
// arbitrary.
// selectTemplate returns the template a request for these scopes is built
// from, and the scope that chose it.
//
// Non-standard scopes are considered before standard ones so "openid", which
// usually comes first and which several templates carry, does not decide it.
// Within each pass the caller's scope order wins, so selection is a pure
// function of the request - it must be, because the request and the claim
// mapping have to agree on one template.
func (pb *PresentationBuilder) selectTemplate(scopes []string) (PresentationRequestTemplate, bool) {
	for _, standard := range []bool{false, true} {
		for _, scope := range scopes {
			if StandardOIDCScopes[scope] != standard {
				continue
			}
			if templateID, ok := pb.scopeIndex[scope]; ok {
				if template, ok := pb.templates[templateID]; ok {
					return template, true
				}
			}
		}
	}
	return nil, false
}

// TemplateRequestsW3C reports whether the template these scopes select asks
// for a W3C credential in any of its credential queries.
//
// For the verifier's "could this session have asked for a W3C credential?"
// question, which is asked exactly when the persisted request cannot be
// read back - so it has to be answered from configuration rather than from
// the request. Reading common.credential_metadata alone was not enough: a
// template names its own credential queries with arbitrary ids and may
// request ldp_vc for a scope that configures no metadata at all, and such a
// session then looked like it could not have wanted W3C.
//
// Scope-selected rather than "any template anywhere", because that is how
// the request was built: selectTemplate is a pure function of the scopes,
// so this asks about the same template the session actually used.
func (pb *PresentationBuilder) TemplateRequestsW3C(scopes []string) bool {
	if pb == nil {
		return false
	}
	template, ok := pb.selectTemplate(scopes)
	if !ok {
		return false
	}
	dcql := template.GetDCQLQuery()
	if dcql == nil {
		return false
	}
	for _, credential := range dcql.Credentials {
		if IsW3CVCFormatIdentifier(credential.Format) {
			return true
		}
	}
	return false
}

func (pb *PresentationBuilder) TemplateDCQLQuery(_ context.Context, scopes []string) (*DCQL, []string, bool) {
	if len(scopes) == 0 {
		return nil, nil, false
	}

	template, ok := pb.selectTemplate(scopes)
	if !ok {
		return nil, nil, false
	}
	dcql := template.GetDCQLQuery()
	if dcql == nil {
		return nil, nil, false
	}

	// A copy, so a caller completing the query in place (see the verifier's
	// augmentVCTValuesFromConfig) cannot edit the template every later request
	// is built from.
	//
	// The template's own oidc_scopes come back with it: they are the only
	// record of which requested scopes this query is meant to answer, and a
	// caller pairing scopes to queries has nothing else to go on for a scope
	// that configures no credential.
	return copyDCQL(dcql), slices.Clone(template.GetOIDCScopes()), true
}

// copyAnyMap deep-copies an opaque JSON tree.
//
// Nil in, nil out, so a copied query is indistinguishable from the
// original.
//
// This copied through the encoding, which was tidy and quietly REPAIRED
// what it copied. A raw leaf is bytes, and re-parsing bytes is not a copy
// of them: Params{"payload": json.RawMessage(`{"x":1,"x":2}`)} came back
// as {"x":2}. The original emits both members - that is what a raw leaf is
// FOR, since a Verifier sends a deliberately malformed request to see what
// a wallet does with it - so templating one silently changed the request
// under test. Member order and a number's spelling were lost the same way.
//
// So the tree is walked instead, and the containers a JSON tree is made of
// are copied structurally. Anything else still goes through the encoding,
// which keeps the original promise: a shape this build does not model is
// normalised rather than aliased, and the walk does not have to be taught
// every type a Verifier might configure.
func copyAnyMap(src map[string]any) map[string]any {
	return copyAnyMapAt(src, &copyPath{})
}

// copyPath is the walk's position: how deep it is, and which containers
// are on the route it took to get there.
//
// On the PATH, not merely visited. The same container reached twice by
// different routes is a DAG, which is legitimate and has to be copied
// both times; only a container reachable from itself is a cycle.
//
// Depth alone was not enough. It bounds stack usage, not total work, so
// a map holding ITSELF TWICE - m["a"] = m, m["b"] = m - still expanded
// into a binary tree and burned 2^65 steps before the bound could stop
// it. Identity stops it at the first repeat.
type copyPath struct {
	depth int
	seen  map[[2]uintptr]bool
}

// containerKey identifies a container on the path.
//
// The length is part of it because two sub-slices of one array share a
// data pointer: keying on the pointer alone would call a legitimate
// nested slice a cycle and alias it instead of copying it. A map or a
// pointer has no length and uses zero.
func containerKey(pointer uintptr, length int) [2]uintptr {
	return [2]uintptr{pointer, uintptr(length)}
}

// enter records a container as being on the active path, reporting false
// if it already is - which means the walk has come back to it.
func (p *copyPath) enter(key [2]uintptr) bool {
	if p.seen[key] {
		return false
	}
	if p.seen == nil {
		p.seen = make(map[[2]uintptr]bool, 4)
	}
	p.seen[key] = true
	p.depth++
	return true
}

func (p *copyPath) leave(key [2]uintptr) {
	delete(p.seen, key)
	p.depth--
}

// maxCopyDepth bounds the walk below.
//
// A tree that came off the wire is shallow; a programmatically built one
// can contain a CYCLE, and the walk followed it until the stack died -
// a self-referencing field tagged json:"-" is invisible to Marshal, so
// the value serialises fine and only copying it crashes. Past this depth
// the value goes to encodeCopy, which keeps it as the bytes it marshals
// to, and reports the cycle as an error that leaves the original in
// place. The bound costs nothing in fidelity now that the fallback is
// byte-exact.
const maxCopyDepth = 64

func copyAnyMapAt(src map[string]any, path *copyPath) map[string]any {
	if src == nil {
		return nil
	}
	key := containerKey(reflect.ValueOf(src).Pointer(), 0)
	if !path.enter(key) {
		// Already on the path: this map contains itself. Nothing can be
		// copied faithfully from here, and Marshal refuses such a value
		// anyway, so the original is left in place.
		return src
	}
	defer path.leave(key)

	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = copyAnyValueAt(value, path)
	}
	return dst
}

// copyAnyValue deep-copies one node of an opaque JSON tree.
func copyAnyValue(src any) any {
	return copyAnyValueAt(src, &copyPath{})
}

func copyAnyValueAt(src any, path *copyPath) any {
	if path.depth > maxCopyDepth {
		return encodeCopy(src)
	}
	switch typed := src.(type) {
	case nil, bool, string, float64, json.Number:
		// Immutable, so sharing one is not aliasing.
		return src

	case json.RawMessage:
		// Bytes, copied as bytes. Everything a raw leaf exists to carry -
		// a duplicate member, member order, a number written the long way -
		// survives only if it is never re-parsed.
		//
		// Allocated with a length, because appending to a nil slice
		// returns a NIL one: an empty-but-present raw leaf would come out
		// nil, and the two do not mean the same thing. An empty one fails
		// to marshal ("unexpected end of JSON input") while nil marshals
		// as null, so flattening them turns a request that cannot be sent
		// into one that quietly says null - the copy repairing what it
		// copies, which is the thing this whole path exists to stop.
		if typed == nil {
			return src
		}
		return append(make(json.RawMessage, 0, len(typed)), typed...)

	case map[string]any:
		return copyAnyMapAt(typed, path)

	case []any:
		if typed == nil {
			// A nil slice encodes as null and an empty one as [], so
			// allocating here would send [] where the query said null.
			return src
		}
		// This branch is a FAST PATH around the reflective walk, and it
		// was skipping that walk's cycle guard with it: s[0] = s recursed
		// here without ever recording the slice, so the guards on maps
		// and on typed slices did nothing and the stack died.
		key := containerKey(reflect.ValueOf(typed).Pointer(), len(typed))
		if !path.enter(key) {
			return src
		}
		defer path.leave(key)

		dst := make([]any, len(typed))
		for i, value := range typed {
			dst[i] = copyAnyValueAt(value, path)
		}
		return dst

	default:
		return copyTypedContainerAt(src, path)
	}
}

// copyTypedContainer copies a map or slice whose element type is concrete,
// which the cases above cannot name.
//
// map[string]json.RawMessage and []json.RawMessage are the ones a caller
// is likely to build, and sending them through the encoding would re-parse
// the raw leaves inside them - collapsing a duplicate member exactly as
// copying the whole tree through the encoding used to. The container is
// copied by reflection while every element goes back through
// copyAnyValue, so a raw leaf survives at any depth inside a typed one.
//
// Anything that is not a map or a slice, or whose elements will not fit
// back into it, still goes through the encoding: a shape this build does
// not model is normalised rather than aliased.
func copyTypedContainerAt(src any, path *copyPath) any {
	value := reflect.ValueOf(src)
	kind := value.Kind()

	// A SCALAR is immutable, so sharing one is not aliasing - and this
	// has to come first, because sending one through the encoding changes
	// its TYPE. An int came back as a json.Number, which is not
	// assignable to int, so the container holding it failed the
	// assignability check below and was condemned to the encoding whole:
	// a struct with a Count int beside a raw payload had the payload
	// collapsed because of the Count. Testing the KIND rather than naming
	// types also covers a named scalar, say type Count int.
	switch kind {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128,
		reflect.String:
		return src
	}

	// A value with its OWN MarshalJSON is snapshotted whole. A
	// structural copy keeps the container's named type, and so keeps that
	// method, while the elements inside it can come back as different
	// types - a named map[string]any whose marshaller expects a
	// time.Time element would find a json.RawMessage there, and
	// marshalling the copied request would fail. encodeCopy keeps the
	// bytes the marshaller produced, which is what the request is.
	if implementsMarshaler(value.Type()) {
		return encodeCopy(src)
	}

	// A POINTER to a raw leaf is a raw leaf. *json.RawMessage went
	// straight to the encoding, where re-parsing collapsed a duplicate
	// member exactly as it did for the value form - so a template
	// holding one still had its negative request repaired while the
	// unpointered spelling beside it was preserved.
	if kind == reflect.Pointer {
		if value.IsNil() {
			return src
		}
		key := containerKey(value.Pointer(), 0)
		if !path.enter(key) {
			return src // already on the path: a cycle through this pointer
		}
		defer path.leave(key)

		copied, ok := copyReflectedAt(value.Elem().Interface(), value.Type().Elem(), path)
		if !ok {
			return encodeCopy(src)
		}
		pointer := reflect.New(value.Type().Elem())
		pointer.Elem().Set(copied)
		return pointer.Interface()
	}

	// An ARRAY is a slice that cannot grow: the same elements, the same
	// raw leaves, but reflect.Array is not reflect.Slice, so
	// [2]json.RawMessage went to the encoding and had its duplicates
	// collapsed. Arrays are values, so there is no nil to preserve.
	if kind == reflect.Array {
		dst := reflect.New(value.Type()).Elem()
		for i := range value.Len() {
			copied, ok := copyReflectedAt(value.Index(i).Interface(), value.Type().Elem(), path)
			if !ok {
				return encodeCopy(src)
			}
			dst.Index(i).Set(copied)
		}
		return dst.Interface()
	}

	if kind != reflect.Map && kind != reflect.Slice {
		return encodeCopy(src)
	}
	if value.IsNil() {
		return src
	}

	length := 0
	if kind == reflect.Slice {
		length = value.Len()
	}
	key := containerKey(value.Pointer(), length)
	if !path.enter(key) {
		return src // already on the path: a cycle through this container
	}
	defer path.leave(key)

	element := value.Type().Elem()
	if kind == reflect.Map {
		dst := reflect.MakeMapWithSize(value.Type(), value.Len())
		for iter := value.MapRange(); iter.Next(); {
			copied, ok := copyReflectedAt(iter.Value().Interface(), element, path)
			if !ok {
				return encodeCopy(src)
			}
			dst.SetMapIndex(iter.Key(), copied)
		}
		return dst.Interface()
	}

	dst := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
	for i := range value.Len() {
		copied, ok := copyReflectedAt(value.Index(i).Interface(), element, path)
		if !ok {
			return encodeCopy(src)
		}
		dst.Index(i).Set(copied)
	}
	return dst.Interface()
}

// copyReflected copies one element of a typed container, reporting
// whether the result fits back into it.
//
// A nil interface element is the case worth naming: copyAnyValue returns
// it unchanged, reflect.ValueOf gives an INVALID Value for it, and
// treating that as "does not fit" sent the whole container through the
// encoding - re-parsing every raw leaf sitting beside the nil and
// collapsing any duplicate member inside them. A named container, say
// type Object map[string]any, reaches here holding exactly that mix.
func copyReflectedAt(src any, element reflect.Type, path *copyPath) (reflect.Value, bool) {
	copied := reflect.ValueOf(copyAnyValueAt(src, path))
	if !copied.IsValid() {
		// Nil, which every element type that can hold it has a zero for.
		if element.Kind() == reflect.Interface {
			return reflect.Zero(element), true
		}
		return reflect.Value{}, false
	}
	if !copied.Type().AssignableTo(element) {
		return reflect.Value{}, false
	}
	return copied, true
}

// A value that serialises ITSELF is snapshotted whole: its output is the
// request, and what is inside it is none of this walk's business.
//
// encoding/json dispatches to more than one interface, and recognising
// only some of them is what repeatedly let a container through. The ones
// below are the stdlib's; MarshalJSONTo is matched by NAME because it
// belongs to encoding/json/v2, which this module reaches through the
// jsonv2 GOEXPERIMENT rather than by import - naming it keeps this
// correct whether that experiment is on or off, and snapshotting a type
// json would NOT have dispatched to costs nothing, since encodeCopy
// reproduces its bytes either way.
var marshalerTypes = []reflect.Type{
	reflect.TypeOf((*json.Marshaler)(nil)).Elem(),
	reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem(),
	reflect.TypeOf((*encoding.TextAppender)(nil)).Elem(),
}

var marshalerMethods = []string{"MarshalJSONTo"}

func implementsMarshaler(t reflect.Type) bool {
	pointer := reflect.PointerTo(t)
	for _, marshaler := range marshalerTypes {
		if t.Implements(marshaler) || pointer.Implements(marshaler) {
			return true
		}
	}
	for _, name := range marshalerMethods {
		if _, found := t.MethodByName(name); found {
			return true
		}
		if _, found := pointer.MethodByName(name); found {
			return true
		}
	}
	return false
}

// encodeCopy copies through the encoding, normalising a shape this build
// does not model rather than aliasing it.
func encodeCopy(src any) any {
	encoded, err := json.Marshal(src)
	if err != nil {
		// Unreachable for a tree that came off the wire or out of
		// configuration; aliasing the original is better than losing it.
		return src
	}
	// As BYTES, not re-parsed. Re-parsing them was the whole defect: a
	// duplicate member, member order and a number's spelling are all lost
	// by a decode, and a value that reaches here is precisely the one
	// nothing else knows how to preserve. Held as a json.RawMessage the
	// copy marshals to the same bytes as the original, which is all this
	// copy has ever needed to guarantee.
	return json.RawMessage(encoded)
}

// copyDCQL creates a deep copy of a DCQL query
func copyDCQL(src *DCQL) *DCQL {
	if src == nil {
		return nil
	}

	dst := &DCQL{
		Credentials: make([]CredentialQuery, len(src.Credentials)),
		// CredentialSets is only set if source has elements.
		// We use nil (not empty slice) to ensure consistent behavior:
		// nil is unambiguous for both JSON omitempty and validator omitempty.
	}

	// Only create CredentialSets if source has elements
	if len(src.CredentialSets) > 0 {
		dst.CredentialSets = make([]CredentialSetQuery, len(src.CredentialSets))
	}

	// Copy credentials
	for i, cred := range src.Credentials {
		meta := MetaQuery{
			DoctypeValue: cred.Meta.DoctypeValue,
			PPIDContext:  cred.Meta.PPIDContext,
		}
		if len(cred.Meta.VCTValues) > 0 {
			meta.VCTValues = append([]string{}, cred.Meta.VCTValues...)
		}
		if len(cred.Meta.TypeValues) > 0 {
			meta.TypeValues = make([][]string, len(cred.Meta.TypeValues))
			for j, tv := range cred.Meta.TypeValues {
				meta.TypeValues[j] = append([]string{}, tv...)
			}
		}
		if len(cred.Meta.ZKSystemType) > 0 {
			meta.ZKSystemType = make([]ZKSystemTypeSpec, len(cred.Meta.ZKSystemType))
			for j, spec := range cred.Meta.ZKSystemType {
				params := make(map[string]string, len(spec.Params))
				maps.Copy(params, spec.Params)
				meta.ZKSystemType[j] = ZKSystemTypeSpec{
					ID:     spec.ID,
					System: spec.System,
					Params: params,
				}
			}
		}
		dst.Credentials[i] = CredentialQuery{
			ID:     cred.ID,
			Format: cred.Format,

			Meta: meta,
		}
		if cred.Multiple != nil {
			v := *cred.Multiple
			dst.Credentials[i].Multiple = &v
		}
		if cred.RequireCryptographicHolderBinding != nil {
			v := *cred.RequireCryptographicHolderBinding
			dst.Credentials[i].RequireCryptographicHolderBinding = &v
		}

		// Copy trusted authorities
		if len(cred.TrustedAuthorities) > 0 {
			dst.Credentials[i].TrustedAuthorities = make([]TrustedAuthority, len(cred.TrustedAuthorities))
			for j, ta := range cred.TrustedAuthorities {
				dst.Credentials[i].TrustedAuthorities[j] = TrustedAuthority{
					Type:   ta.Type,
					Values: append([]string{}, ta.Values...),
				}
			}
		}

		// Copy claims
		if len(cred.Claims) > 0 {
			dst.Credentials[i].Claims = make([]ClaimQuery, len(cred.Claims))
			for j, claim := range cred.Claims {
				pathCopy := make([]*string, len(claim.Path))
				for k, p := range claim.Path {
					if p != nil {
						s := *p
						pathCopy[k] = &s
					}
				}
				var valuesCopy []any
				if claim.Values != nil {
					valuesCopy = append([]any{}, claim.Values...)
				}
				dst.Credentials[i].Claims[j] = ClaimQuery{
					ID:     claim.ID,
					Path:   pathCopy,
					Values: valuesCopy,
				}
			}
		}

		// Copy the circuit_zk request. Params and Extra are opaque trees
		// this package passes through unchanged, so they are deep-copied
		// through their JSON encoding rather than walked field by field.
		if len(cred.Req) > 0 {
			dst.Credentials[i].Req = make([]ReqItem, len(cred.Req))
			for j, item := range cred.Req {
				dst.Credentials[i].Req[j] = ReqItem{
					ID:     item.ID,
					Return: item.Return,
					Params: copyAnyMap(item.Params),
					Extra:  copyAnyMap(item.Extra),
				}
			}
		}
		dst.Credentials[i].Extra = copyAnyMap(cred.Extra)
		if cred.Raw != nil {
			dst.Credentials[i].Raw = append(json.RawMessage(nil), cred.Raw...)
		}

		// Copy claim sets
		if len(cred.ClaimSet) > 0 {
			dst.Credentials[i].ClaimSet = make([][]string, len(cred.ClaimSet))
			for j, cs := range cred.ClaimSet {
				dst.Credentials[i].ClaimSet[j] = append([]string{}, cs...)
			}
		}
	}

	// Copy credential sets
	for i, cs := range src.CredentialSets {
		dst.CredentialSets[i] = CredentialSetQuery{
			Options: make([][]string, len(cs.Options)),
		}
		if cs.Required != nil {
			v := *cs.Required
			dst.CredentialSets[i].Required = &v
		}
		for j, opt := range cs.Options {
			dst.CredentialSets[i].Options[j] = append([]string{}, opt...)
		}
	}

	return dst
}

// createGenericDCQL creates a generic DCQL query when no specific templates match
func (pb *PresentationBuilder) createGenericDCQL() *DCQL {
	return &DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "credential_generic",
				Format: "vc+sd-jwt",
				Meta: MetaQuery{
					VCTValues: []string{}, // Empty - accept any VCT
				},
			},
		},
	}
}

// StandardOIDCScopes contains scopes defined by OpenID Connect Core.
// These are protocol-level scopes that are optional for credential matching.
// The "openid" scope is REQUIRED by the OIDC specification and will always
// be present, but it does not need to be mapped to a credential.
var StandardOIDCScopes = map[string]bool{
	"openid":         true,
	"profile":        true,
	"email":          true,
	"address":        true,
	"phone":          true,
	"offline_access": true,
}

// FilterStandardScopes removes standard OIDC scopes from the list.
// This is a utility function that can be used when you specifically need
// to identify scopes that are not standard OIDC scopes. Note that credential
// matching logic does NOT use this - all scopes (including standard ones)
// are considered for matching to allow optional credential mappings.
func FilterStandardScopes(scopes []string) []string {
	filtered := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !StandardOIDCScopes[scope] {
			filtered = append(filtered, scope)
		}
	}
	return filtered
}

// FindTemplateByScopes finds a template that matches the given OIDC scopes
// Returns the first template where all requested scopes are present in the template's scopes
func (pb *PresentationBuilder) FindTemplateByScopes(scopes []string) PresentationRequestTemplate {
	if len(scopes) == 0 {
		return nil
	}

	// The SAME rule the request was built with. Ranging pb.templates and
	// taking any scope overlap picked a different template on different runs -
	// map order is random, and the shipped eudi_pid_basic and eduid_basic both
	// declare "profile" - so a request for "pid profile" could be built from
	// the PID template and then have eduID's claim mappings applied to the
	// credential that came back.
	template, ok := pb.selectTemplate(scopes)
	if !ok {
		return nil
	}
	return template
}

// GetClaimMappings is a helper to extract claim mappings from a template
// Returns nil if the template doesn't implement this method
func GetClaimMappings(template PresentationRequestTemplate) map[string]string {
	if t, ok := template.(interface {
		GetClaimMappings() map[string]string
	}); ok {
		return t.GetClaimMappings()
	}
	return nil
}

// ListTemplates returns all templates
func (pb *PresentationBuilder) ListTemplates() []PresentationRequestTemplate {
	templates := make([]PresentationRequestTemplate, 0, len(pb.templates))
	for _, template := range pb.templates {
		templates = append(templates, template)
	}
	return templates
}

// GetTemplate returns a specific template by ID
func (pb *PresentationBuilder) GetTemplate(templateID string) (PresentationRequestTemplate, error) {
	template, ok := pb.templates[templateID]
	if !ok {
		return nil, fmt.Errorf("template %s not found", templateID)
	}
	return template, nil
}
