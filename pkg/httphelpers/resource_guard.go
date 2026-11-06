package httphelpers

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/resourcereach"

	"github.com/gin-gonic/gin"
)

// resourceGuardKey is the gin context key of the request's resourceGuard.
const resourceGuardKey = "spocp_resource_guard"

// resourceGuard answers the SPOCP resource check for one authenticated subject.
//
// The authorization middleware puts it on the context. Binding.Request runs it
// again on the selectors it bound, so the selector a handler receives is one
// the policy allows however the request spelled it.
type resourceGuard struct {
	engine  *SafeEngine
	service string
	subject string
	log     *logger.Log
}

// allows reports whether the policy allows every pair. It logs the first denial.
func (g resourceGuard) allows(c *gin.Context, pairs []resourcePair) bool {
	for _, p := range pairs {
		query := BuildSPOCPQuery(g.service, c.Request.Method, c.FullPath(), g.subject, p.authenticSource, p.scope)
		if !g.engine.QueryElement(query) {
			g.log.Info("spocp_denied", "subject", g.subject, "service", g.service, "method", c.Request.Method, "path", c.FullPath(),
				"authentic_source", p.authenticSource, "scope", p.scope, "req_id", c.GetString("req_id"))
			return false
		}
	}
	return true
}

// normalizeResourcePairs turns pairs read from a request into the pairs the
// policy is asked about.
func normalizeResourcePairs(c *gin.Context, pairs []resourcePair) []resourcePair {
	// Inject synthetic scope for identity mapping endpoints — these have
	// authentic_source but no scope in the document model.
	if strings.Contains(c.FullPath(), "/identity/mapping") {
		for i := range pairs {
			if pairs[i].authenticSource != "" && pairs[i].scope == "" {
				pairs[i].scope = resourcereach.IdentityMappingScope
			}
		}
	}

	return deduplicatePairs(pairs)
}

// authorizeBoundSelectors checks the selectors held by the bound request v
// against the guard of the middleware that authenticated the request. A request
// with no guard runs without SPOCP rules.
func authorizeBoundSelectors(c *gin.Context, v any) error {
	value, ok := c.Get(resourceGuardKey)
	if !ok {
		return nil
	}
	guard, ok := value.(resourceGuard)
	if !ok {
		return fmt.Errorf("context key %s holds %T", resourceGuardKey, value)
	}

	pairs, err := boundSelectors(v)
	if err != nil {
		return err
	}
	if !guard.allows(c, normalizeResourcePairs(c, pairs)) {
		return helpers.NewErrorDetailsWithStatus("insufficient_permissions",
			"the request selects an authentic_source or scope this caller is not allowed", http.StatusForbidden)
	}
	return nil
}

// boundSelectors returns one pair for each struct in v that holds a selector
// field, at any depth of typed fields. Values under an interface type, such as
// document_data, are client data. A selector field that holds no string is an
// error, so a request type the guard cannot read reaches no handler.
func boundSelectors(v any) ([]resourcePair, error) {
	var pairs []resourcePair
	err := collectSelectors(reflect.ValueOf(v), &pairs)
	return pairs, err
}

func collectSelectors(v reflect.Value, pairs *[]resourcePair) error {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			return collectSelectors(v.Elem(), pairs)
		}
	case reflect.Struct:
		return collectStructSelectors(v, pairs)
	case reflect.Map:
		for iter := v.MapRange(); iter.Next(); {
			if err := collectSelectors(iter.Value(), pairs); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			if err := collectSelectors(v.Index(i), pairs); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectStructSelectors(v reflect.Value, pairs *[]resourcePair) error {
	var pair resourcePair
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() && !field.Anonymous {
			continue
		}
		value := v.Field(i)
		selector := pair.selectorOf(field)
		if selector == nil {
			if err := collectSelectors(value, pairs); err != nil {
				return err
			}
			continue
		}
		if value.Kind() != reflect.String {
			return fmt.Errorf("selector field %s.%s is a %s; the SPOCP guard reads a string", t, field.Name, value.Kind())
		}
		*selector = value.String()
	}
	if pair != (resourcePair{}) {
		*pairs = append(*pairs, pair)
	}
	return nil
}

// selectorOf returns the member of p that field fills, and nil for a field that
// holds no selector.
func (p *resourcePair) selectorOf(field reflect.StructField) *string {
	switch {
	case isSelectorField(field, "AuthenticSource", "authentic_source"):
		return &p.authenticSource
	case isSelectorField(field, "Scope", "scope"):
		return &p.scope
	}
	return nil
}

func isSelectorField(field reflect.StructField, goName, jsonName string) bool {
	tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	return field.Name == goName || tag == jsonName
}
