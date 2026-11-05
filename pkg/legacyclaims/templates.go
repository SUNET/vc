package legacyclaims

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/goccy/go-yaml/ast"
	"gopkg.in/yaml.v2"
)

// passThrough is the claim_mappings value, and the entry of the earlier
// release's map, that maps every claim under its own name.
const passThrough = "*"

// UpgradeTemplates upgrades a presentation request file: one template, or
// a list of them under "templates". It rewrites the claim paths of each
// dcql, and records each claim_mappings written as the earlier release's
// map from dotted claim names to OIDC claims. With convert, it rewrites
// such a map into the keyed form when the keyed form maps the same claims.
func UpgradeTemplates(d *Document, convert bool) error {
	if d.root == nil {
		return nil
	}
	return d.fail(d.upgradeTemplates(convert))
}

// upgradeTemplates is UpgradeTemplates for a document with a root.
func (d *Document) upgradeTemplates(convert bool) error {
	templates, err := templateNodes(d.root)
	if err != nil {
		return err
	}
	for _, template := range templates {
		queries, err := d.templateDCQL(template)
		if err != nil {
			return err
		}
		if err := d.claimMappings(template, queries, convert); err != nil {
			return err
		}
	}
	return nil
}

// templateNodes returns the templates of a presentation request file: the
// entries of a non-empty "templates" list, or the file itself.
func templateNodes(root ast.Node) ([]ast.Node, error) {
	list, err := descend(root, "templates")
	if err != nil {
		return nil, err
	}
	templates, err := items(list)
	if err != nil || len(templates) > 0 {
		return templates, err
	}
	return []ast.Node{root}, nil
}

// query is a credential query of a template's dcql.
type query struct {
	id     string
	format string
	// multiple is set when the query allows several presentations.
	multiple bool
}

// templateDCQL upgrades the claim paths of a template's dcql, which main
// read as lists of strings and nulls, and returns its credential queries.
func (d *Document) templateDCQL(template ast.Node) ([]query, error) {
	credentials, err := descend(template, "dcql", "credentials")
	if err != nil {
		return nil, err
	}
	list, err := items(credentials)
	if err != nil {
		return nil, err
	}
	queries := make([]query, 0, len(list))
	for _, credential := range list {
		claims, err := descend(credential, "claims")
		if err != nil {
			return nil, err
		}
		claimList, err := items(claims)
		if err != nil {
			return nil, err
		}
		for _, claim := range claimList {
			path, err := descend(claim, "path")
			if err != nil {
				return nil, err
			}
			if err := d.stringPath(path, false); err != nil {
				return nil, err
			}
		}
		id, err := scalarValue(credential, "id")
		if err != nil {
			return nil, err
		}
		format, err := scalarValue(credential, "format")
		if err != nil {
			return nil, err
		}
		multiple, err := scalarValue(credential, "multiple")
		if err != nil {
			return nil, err
		}
		var allows bool
		if multiple != "" {
			if err := yaml.Unmarshal([]byte(multiple), &allows); err != nil {
				return nil, fmt.Errorf("%s: multiple: %w", credential.GetPath(), err)
			}
		}
		queries = append(queries, query{id: id, format: format, multiple: allows})
	}
	return queries, nil
}

// scalarValue returns the text of the scalar under key of mapping n, or
// "" when it is absent or null.
func scalarValue(n ast.Node, key string) (string, error) {
	value, err := descend(n, key)
	if err != nil || value == nil {
		return "", err
	}
	value, err = unwrap(value)
	if err != nil || isNull(value) {
		return "", err
	}
	if literal, ok := value.(*ast.LiteralNode); ok {
		return literal.Value.Value, nil
	}
	text, ok := dottedName(value)
	if !ok {
		return "", fmt.Errorf("%s is no scalar", value.GetPath())
	}
	return text, nil
}

// nameMapping is one entry of the earlier release's claim_mappings map.
type nameMapping struct {
	entry *ast.MappingValueNode
	name  string
	// claim is the OIDC claim, and claimText its text as written.
	claim, claimText string
}

// claimMappings records the claim_mappings of a template when it is the
// earlier release's map, and with convert rewrites it into the keyed form
// when that form maps the same claims.
func (d *Document) claimMappings(template ast.Node, queries []query, convert bool) error {
	entry, err := child(template, "claim_mappings")
	if err != nil || entry == nil {
		return err
	}
	mappings, ok, err := d.nameMappings(entry.Value)
	if err != nil || !ok {
		return err
	}
	old := renderNameMappings(mappings)
	conversion := convertNameMappings(mappings, queries)
	d.rewrites = append(d.rewrites, Rewrite{
		File: d.file,
		Path: entry.GetPath(),
		Line: entry.Key.GetToken().Position.Line,
		Old:  old,
		New:  conversion.text,
		Note: conversion.note,
	})
	if !convert || conversion.note != "" {
		return nil
	}
	return d.rewriteMappings(entry, mappings, conversion)
}

// nameMappings returns the entries of a claim_mappings map whose values
// are all scalars: the earlier release's form.
func (d *Document) nameMappings(n ast.Node) ([]nameMapping, bool, error) {
	n, err := unwrap(n)
	if err != nil {
		return nil, false, err
	}
	switch n.(type) {
	case *ast.MappingNode, *ast.MappingValueNode:
	default:
		return nil, false, nil
	}
	list, err := entries(n)
	if err != nil {
		return nil, false, err
	}
	mappings := make([]nameMapping, 0, len(list))
	for _, entry := range list {
		value, err := unwrap(entry.Value)
		if err != nil {
			return nil, false, err
		}
		claim, text, ok, err := d.claimOf(value)
		if err != nil || !ok {
			return nil, false, err
		}
		name, err := keyOf(entry)
		if err != nil {
			return nil, false, err
		}
		mappings = append(mappings, nameMapping{entry: entry, name: name, claim: claim, claimText: text})
	}
	return mappings, true, nil
}

// claimOf returns the OIDC claim a value of the earlier release's map
// names, and its flow text. It reports false for a collection.
func (d *Document) claimOf(value ast.Node) (claim, text string, ok bool, err error) {
	switch v := value.(type) {
	case nil, *ast.NullNode:
		return "", `""`, true, nil
	case *ast.MappingNode, *ast.MappingValueNode, *ast.SequenceNode:
		return "", "", false, nil
	case *ast.LiteralNode:
		return v.Value.Value, strconv.Quote(v.Value.Value), true, nil
	}
	claim, ok = dottedName(value)
	if !ok {
		return "", "", false, fmt.Errorf("%s is no OIDC claim name", value.GetPath())
	}
	text, err = d.text(value)
	if err != nil {
		return "", "", false, err
	}
	return claim, strings.TrimSpace(text), true, nil
}

// renderNameMappings renders the earlier release's map as a flow mapping.
func renderNameMappings(mappings []nameMapping) string {
	parts := make([]string, len(mappings))
	for i, m := range mappings {
		parts[i] = scalarText(m.name) + ": " + m.claimText
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// conversion is the keyed form of an earlier release's map, as flow text,
// with what keeps the converter from writing it.
type conversion struct {
	text string
	// note says why the keyed form maps other claims; empty when it maps
	// the same ones.
	note string
	// passThrough is set when the keyed form is "*".
	passThrough bool
	// queryID and paths are the keyed form's query and each entry's path,
	// in entry order, for a convertible map that is no pass-through.
	queryID string
	paths   []claimpath.Pointer
}

// convertNameMappings returns the keyed form of the earlier release's map
// for a template with the credential queries queries.
//
// The earlier release merged the claims of all presentations, and read a
// name split on dots: in a presented mdoc it finds an element of
// org.iso.18013.5.1 under its bare identifier, and no other. The keyed
// form maps each presentation through the entries of its own query, and
// refuses two different values for one OIDC claim. So only a map of a
// template with one query converts, and in an mdoc, only bare names do.
func convertNameMappings(mappings []nameMapping, queries []query) conversion {
	if slices.ContainsFunc(mappings, func(m nameMapping) bool { return m.name == passThrough && m.claim == passThrough }) {
		return conversion{text: `"*"`, passThrough: true}
	}
	suggested, unreadable := suggestKeyed(mappings, queries)
	if unreadable != "" {
		return conversion{text: suggested, note: unreadable}
	}
	if i := slices.IndexFunc(mappings, func(m nameMapping) bool { return m.name == passThrough }); i >= 0 {
		return conversion{text: suggested, note: fmt.Sprintf("the earlier form skips the entry %q: %q; delete it", passThrough, mappings[i].claim)}
	}
	switch {
	case len(queries) == 0:
		return conversion{text: suggested, note: "the template has no credential query to key the mappings by"}
	case len(queries) > 1:
		return conversion{text: suggested, note: fmt.Sprintf("the template requests %d credentials; the keyed form maps each presentation through the entries of its own query, and refuses two values for one OIDC claim", len(queries))}
	case queries[0].multiple:
		return conversion{text: suggested, note: fmt.Sprintf("the query %q allows several presentations; the keyed form refuses two values for one OIDC claim", queries[0].id)}
	}
	q := queries[0]
	claims := make(map[string]string, len(mappings))
	paths := make([]claimpath.Pointer, 0, len(mappings))
	for _, m := range mappings {
		if m.claim == "" {
			return conversion{text: suggested, note: fmt.Sprintf("%q maps to an empty OIDC claim", m.name)}
		}
		if other, ok := claims[m.claim]; ok {
			return conversion{text: suggested, note: fmt.Sprintf("%q and %q both map to the OIDC claim %q", other, m.name, m.claim)}
		}
		claims[m.claim] = m.name
		path, note := mappedClaim(q.format, m.name)
		if note != "" {
			return conversion{text: suggested, note: note}
		}
		paths = append(paths, path)
	}
	return conversion{text: suggested, queryID: q.id, paths: paths}
}

// mappedClaim returns the claim the earlier release's mapper read for a
// name in a presentation of format, or why the keyed form reads another.
func mappedClaim(format, name string) (claimpath.Pointer, string) {
	if openid4vp.IsMdocFormat(format) || openid4vp.IsMdocZkFormat(format) {
		switch {
		case strings.Contains(name, "."):
			return claimpath.Pointer{}, fmt.Sprintf("the earlier form splits %q on dots, which reads no namespace-qualified element of a presented mdoc; the keyed form maps the element", name)
		case name == "docType":
			return claimpath.Pointer{}, `the earlier form maps the presented mdoc's document type under "docType", which no claims path pointer names`
		}
		return claimpath.Keys(isoNamespace, name), ""
	}
	path, err := Nested().Dotted(name)
	if err != nil {
		return claimpath.Pointer{}, fmt.Sprintf("%q names no claims path pointer: %v", name, err)
	}
	return path, ""
}

// suggestKeyed renders the keyed form that maps each entry in each query,
// with each name read the way a dotted claim name of a presented
// credential of the query's format reads. The form leaves out each entry
// whose name has no claims path pointer, and the note names the first.
func suggestKeyed(mappings []nameMapping, queries []query) (text, note string) {
	parts := make([]string, 0, len(queries))
	for _, q := range queries {
		reading := Presented(q.format)
		entries := make([]string, 0, len(mappings))
		for _, m := range mappings {
			entry, err := keyedEntry(reading, m)
			if err != nil {
				if note == "" {
					note = fmt.Sprintf("%q names no claims path pointer: %v", m.name, err)
				}
				continue
			}
			entries = append(entries, entry)
		}
		parts = append(parts, scalarText(q.id)+": ["+strings.Join(entries, ", ")+"]")
	}
	return "{" + strings.Join(parts, ", ") + "}", note
}

// keyedEntry renders the keyed entry that maps the name of m, read as
// reading reads it.
func keyedEntry(reading Shape, m nameMapping) (string, error) {
	path, err := reading.Dotted(m.name)
	if err != nil {
		return "", err
	}
	pointer, err := pointerText(path)
	if err != nil {
		return "", err
	}
	return "{path: " + pointer + ", claim: " + m.claimText + "}", nil
}

// rewriteMappings writes a convertible claim_mappings map in the keyed
// form, keeping the comments among its entries.
func (d *Document) rewriteMappings(entry *ast.MappingValueNode, mappings []nameMapping, c conversion) error {
	value, err := unwrap(entry.Value)
	if err != nil {
		return err
	}
	if mapping, ok := value.(*ast.MappingNode); ok && mapping.IsFlowStyle {
		start, end, err := d.span(mapping)
		if err != nil {
			return err
		}
		d.replace(start, end, c.text)
		return nil
	}
	if c.passThrough {
		return d.passThroughBlock(entry, mappings)
	}
	first := mappings[0].entry.Key.GetToken()
	d.insert(d.lineStart(first.Position.Line), strings.Repeat(" ", first.Position.Column-1)+scalarText(c.queryID)+":\n")
	d.indent(first.Position.Line, lastLine(value), 2)
	for i, m := range mappings {
		path, err := pointerText(c.paths[i])
		if err != nil {
			return err
		}
		if err := d.replaceEntry(m.entry, "- {path: "+path+", claim: "+m.claimText+"}"); err != nil {
			return err
		}
	}
	return nil
}

// passThroughBlock writes "*" for a block map that holds "*": "*". The
// value moves behind the key when one entry follows it with no comment
// between. Otherwise "*" replaces the first entry, and the other entries,
// which the earlier form skips, go.
func (d *Document) passThroughBlock(entry *ast.MappingValueNode, mappings []nameMapping) error {
	colon, err := d.offset(entry.Start.Position)
	if err != nil {
		return err
	}
	keyStart, _, err := d.span(mappings[0].entry.Key)
	if err != nil {
		return err
	}
	if len(mappings) == 1 && !strings.Contains(string(d.src[colon+1:keyStart]), "#") {
		end, err := d.valueEnd(mappings[0].entry)
		if err != nil {
			return err
		}
		d.replace(colon+1, end, " "+`"*"`)
		return nil
	}
	for i, m := range mappings {
		text := ""
		if i == 0 {
			text = `"*"`
		}
		if err := d.replaceEntry(m.entry, text); err != nil {
			return err
		}
	}
	return nil
}

// replaceEntry replaces the text of an entry, from its key through its
// value, with text.
func (d *Document) replaceEntry(entry *ast.MappingValueNode, text string) error {
	start, _, err := d.span(entry.Key)
	if err != nil {
		return err
	}
	end, err := d.valueEnd(entry)
	if err != nil {
		return err
	}
	d.replace(start, end, text)
	return nil
}

// IsTemplateFile reports whether a file holds presentation request
// templates: a "templates" list, or one template with a "dcql" query.
func IsTemplateFile(d *Document) bool {
	for _, key := range []string{"templates", "dcql"} {
		entry, err := child(d.root, key)
		if err == nil && entry != nil {
			return true
		}
	}
	return false
}
