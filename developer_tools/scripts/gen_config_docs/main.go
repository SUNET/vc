// Package main generates docs/CONFIGURATION.md from Go struct definitions.
//
// Usage:
//
//	go run developer_tools/scripts/gen_config_docs/main.go [-root /path/to/vc] [-out docs/CONFIGURATION.md]
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"unicode"

	"github.com/iancoleman/strcase"
)

// ---- Data types ----

// DocConstraint represents a struct-level validation rule parsed from
// "// doc:constraint ..." comments in validate.go.
type DocConstraint struct {
	Name        string
	Struct      string
	Applies     []string // Go field names
	Description string
}

type TagInfo struct {
	YAMLName    string
	Omitempty   bool
	Validate    string
	Default     string
	DocExample  string
	DocKey      string
	DocValueKey string
}

type StructDef struct {
	Name    string
	Doc     string
	Fields  []*FieldDef
	PkgName string
}

type FieldDef struct {
	GoName    string
	TypeExpr  ast.Expr
	TypeStr   string
	Doc       string
	InlineDoc string
	Tag       TagInfo
	InlineDef *StructDef
}

type DocSection struct {
	YAMLKey     string
	Title       string
	Description string
	Subs        []*SubSection
}

type SubSection struct {
	Title     string
	Path      string
	AlsoPaths []string
	Desc      string
	Rows      []TableRow
	AfterText string
	TypeName  string // tracks the Go type name for merging paths
}

type TableRow struct {
	Field    string
	Type     string
	Desc     string
	Example  string
	Default  string
	Required string
}

// ---- Type registry ----

type TypeRegistry struct {
	types         map[string]*StructDef
	mapAliases    map[string]string   // named map type -> map value type name
	sliceAliases  map[string]string   // named slice type -> element type name (e.g. "RedirectURIs" -> "string")
	scalarAliases map[string]string   // named scalar type -> underlying type (e.g. "BindingEnforcement" -> "string")
	enumValues    map[string][]string // named type -> ordered list of const values (e.g. "BindingEnforcement" -> ["enforce", "warn", "disabled"])
	fset          *token.FileSet
}

func NewTypeRegistry() *TypeRegistry {
	return &TypeRegistry{
		types:         make(map[string]*StructDef),
		mapAliases:    make(map[string]string),
		sliceAliases:  make(map[string]string),
		scalarAliases: make(map[string]string),
		enumValues:    make(map[string][]string),
		fset:          token.NewFileSet(),
	}
}

func (r *TypeRegistry) ParseDir(dir string) error {
	pkgs, err := parser.ParseDir(r.fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", dir, err)
	}
	for pkgName, pkg := range pkgs {
		for _, file := range pkg.Files {
			r.extractStructs(file, pkgName)
			r.extractEnumConsts(file)
		}
	}
	return nil
}

func (r *TypeRegistry) Lookup(name string) *StructDef {
	if def, ok := r.types[name]; ok {
		return def
	}
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		simple := name[idx+1:]
		if def, ok := r.types[simple]; ok {
			return def
		}
	}
	return nil
}

// LookupInPkg resolves a type name preferring the given package.
// This avoids collisions when different packages define structs with the same name.
func (r *TypeRegistry) LookupInPkg(name, pkgName string) *StructDef {
	// Try package-qualified name first to avoid cross-package collisions
	if pkgName != "" {
		if def, ok := r.types[pkgName+"."+name]; ok {
			return def
		}
	}
	if def, ok := r.types[name]; ok {
		return def
	}
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		simple := name[idx+1:]
		if def, ok := r.types[simple]; ok {
			return def
		}
	}
	return nil
}

func (r *TypeRegistry) extractStructs(file *ast.File, pkgName string) {
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.TYPE {
			continue
		}
		for _, spec := range genDecl.Specs {
			ts := spec.(*ast.TypeSpec)

			// Handle struct types
			if st, ok := ts.Type.(*ast.StructType); ok {
				doc := ""
				if ts.Doc != nil {
					doc = commentText(ts.Doc)
				} else if genDecl.Doc != nil {
					doc = commentText(genDecl.Doc)
				}
				def := &StructDef{Name: ts.Name.Name, Doc: doc, PkgName: pkgName}
				r.parseFields(st, def, pkgName)
				// Register under the pkg-qualified key always; collapse the
				// simple-name entry to a nil sentinel on cross-package
				// collision. A sentinel (rather than a delete) is sticky:
				// a third package with the same identifier cannot reclaim
				// the simple name after two prior packages collided and
				// erased it, which would make the lookup silently resolve
				// to that latecomer.
				if existing, present := r.types[ts.Name.Name]; present {
					if existing != nil && existing.PkgName != pkgName {
						r.types[ts.Name.Name] = nil
					}
				} else {
					r.types[ts.Name.Name] = def
				}
				r.types[pkgName+"."+ts.Name.Name] = def
				continue
			}

			// Handle named map types (e.g., type Clients map[string]*Client)
			if mt, ok := ts.Type.(*ast.MapType); ok {
				valName := resolveTypeName(mt.Value)
				if valName != "" {
					// Store package-qualified value type name so we resolve the correct struct
					qualifiedValName := pkgName + "." + valName
					r.mapAliases[ts.Name.Name] = qualifiedValName
					r.mapAliases[pkgName+"."+ts.Name.Name] = qualifiedValName
				}
			}

			// Handle named slice types (e.g., type RedirectURIs []string)
			if at, ok := ts.Type.(*ast.ArrayType); ok {
				elemName := typeExprStr(at.Elt)
				r.sliceAliases[ts.Name.Name] = elemName
				r.sliceAliases[pkgName+"."+ts.Name.Name] = elemName
			}

			// Handle named scalar types (e.g., type BindingEnforcement string)
			if ident, ok := ts.Type.(*ast.Ident); ok {
				if ident.Name == "string" {
					r.scalarAliases[ts.Name.Name] = "string"
					r.scalarAliases[pkgName+"."+ts.Name.Name] = "string"
				}
			}
		}
	}
}

// extractEnumConsts extracts typed string constants for enum display.
// For example: const BindingEnforcementEnforce BindingEnforcement = "enforce"
func (r *TypeRegistry) extractEnumConsts(file *ast.File) {
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || vs.Type == nil {
				continue
			}
			typeName := typeExprStr(vs.Type)
			// Only collect if this is a known string scalar alias
			if _, isStringAlias := r.scalarAliases[typeName]; !isStringAlias {
				continue
			}
			// Extract the string literal value
			for _, val := range vs.Values {
				lit, ok := val.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				// Unquote the string literal
				s := strings.Trim(lit.Value, "\"")
				r.enumValues[typeName] = append(r.enumValues[typeName], s)
			}
		}
	}
}

// LookupMapValueType returns the struct definition for the value type of a named map alias.
// For example, for "Clients" (which is map[string]*Client), it returns the Client struct def.
func (r *TypeRegistry) LookupMapValueType(name string) *StructDef {
	valName, ok := r.mapAliases[name]
	if !ok {
		if idx := strings.LastIndex(name, "."); idx >= 0 {
			valName, ok = r.mapAliases[name[idx+1:]]
		}
	}
	if !ok {
		return nil
	}
	return r.Lookup(valName)
}

// LookupMapValueTypeInPkg is like LookupMapValueType but prefers the given package.
func (r *TypeRegistry) LookupMapValueTypeInPkg(name, pkgName string) *StructDef {
	var valName string
	var ok bool
	if pkgName != "" {
		valName, ok = r.mapAliases[pkgName+"."+name]
	}
	if !ok {
		valName, ok = r.mapAliases[name]
	}
	if !ok {
		if idx := strings.LastIndex(name, "."); idx >= 0 {
			valName, ok = r.mapAliases[name[idx+1:]]
		}
	}
	if !ok {
		return nil
	}
	return r.LookupInPkg(valName, pkgName)
}

func (r *TypeRegistry) parseFields(st *ast.StructType, def *StructDef, pkgName string) {
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			continue
		}
		// Skip fields without a yaml struct tag
		if field.Tag == nil {
			continue
		}
		tag := parseStructTag(field.Tag.Value)
		if tag.YAMLName == "" || tag.YAMLName == "-" {
			continue
		}
		for _, name := range field.Names {
			if !name.IsExported() {
				continue
			}
			fd := &FieldDef{
				GoName:    name.Name,
				TypeExpr:  field.Type,
				TypeStr:   typeExprStr(field.Type),
				Doc:       commentText(field.Doc),
				InlineDoc: commentText(field.Comment),
				Tag:       tag,
			}
			if inSt, ok := unwrapStruct(field.Type); ok {
				fd.InlineDef = &StructDef{PkgName: pkgName}
				r.parseFields(inSt, fd.InlineDef, pkgName)
			}
			def.Fields = append(def.Fields, fd)
		}
	}
}

// ---- AST helpers ----

func commentText(cg *ast.CommentGroup) string {
	if cg == nil {
		return ""
	}
	var lines []string
	for _, c := range cg.List {
		t := strings.TrimPrefix(c.Text, "//")
		if len(t) > 0 && t[0] == ' ' {
			t = t[1:]
		}
		lines = append(lines, t)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func typeExprStr(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + typeExprStr(t.X)
	case *ast.ArrayType:
		return "[]" + typeExprStr(t.Elt)
	case *ast.MapType:
		return "map[" + typeExprStr(t.Key) + "]" + typeExprStr(t.Value)
	case *ast.SelectorExpr:
		return typeExprStr(t.X) + "." + t.Sel.Name
	case *ast.StructType:
		return "struct"
	case *ast.InterfaceType:
		return "interface{}"
	default:
		return "unknown"
	}
}

func unwrapStruct(expr ast.Expr) (*ast.StructType, bool) {
	switch t := expr.(type) {
	case *ast.StructType:
		return t, true
	case *ast.StarExpr:
		return unwrapStruct(t.X)
	default:
		return nil, false
	}
}

func resolveTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return resolveTypeName(t.X)
	case *ast.SelectorExpr:
		// Preserve the package qualifier (e.g. "pubsub.Config") so
		// LookupInPkg can resolve to the correct package rather than
		// silently fall back to a same-named type in another package.
		if pkgIdent, ok := t.X.(*ast.Ident); ok {
			return pkgIdent.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	default:
		return ""
	}
}

// mapKeyPlaceholder returns the doc_key tag value wrapped in angle brackets,
// or the default "<key>" if no doc_key tag is set.
func mapKeyPlaceholder(tag TagInfo) string {
	if tag.DocKey != "" {
		return "<" + tag.DocKey + ">"
	}
	return "<key>"
}

// ---- Tag parsing ----

func parseStructTag(raw string) TagInfo {
	raw = strings.Trim(raw, "`")
	tag := reflect.StructTag(raw)
	yamlVal, _ := tag.Lookup("yaml")
	parts := strings.SplitN(yamlVal, ",", 2)
	yamlName := parts[0]
	omit := len(parts) > 1 && strings.Contains(parts[1], "omitempty")
	validate, _ := tag.Lookup("validate")
	def, _ := tag.Lookup("default")
	docExample, _ := tag.Lookup("doc_example")
	docKey, _ := tag.Lookup("doc_key")
	docValueKey, _ := tag.Lookup("doc_value_key")
	return TagInfo{YAMLName: yamlName, Omitempty: omit, Validate: validate, Default: def, DocExample: docExample, DocKey: docKey, DocValueKey: docValueKey}
}

// ---- Display helpers ----

func (r *TypeRegistry) displayType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		switch t.Name {
		case "string":
			return "`string`"
		case "bool":
			return "`bool`"
		case "int", "int64", "int32":
			return "`" + t.Name + "`"
		case "uint":
			return "`uint`"
		case "float64":
			return "`float64`"
		default:
			// Resolve named slice aliases (e.g. RedirectURIs -> []string)
			if elem, ok := r.sliceAliases[t.Name]; ok {
				if elem == "string" {
					return "`[]string`"
				}
				if elem == "int" {
					return "`[]int`"
				}
				return "`array`"
			}
			// Resolve named scalar aliases (e.g. BindingEnforcement -> string)
			if underlying, ok := r.scalarAliases[t.Name]; ok {
				if vals, hasEnum := r.enumValues[t.Name]; hasEnum && len(vals) > 0 {
					return "`" + underlying + "` (" + strings.Join(vals, `\|`) + ")"
				}
				return "`" + underlying + "`"
			}
			return "`object`"
		}
	case *ast.StarExpr:
		return r.displayType(t.X)
	case *ast.ArrayType:
		inner := typeExprStr(t.Elt)
		if inner == "string" {
			return "`[]string`"
		}
		if inner == "int" {
			return "`[]int`"
		}
		return "`array`"
	case *ast.MapType:
		return "`object`"
	case *ast.SelectorExpr:
		if t.Sel.Name == "Duration" {
			return "`duration`"
		}
		return "`object`"
	case *ast.StructType:
		return "`object`"
	default:
		return "`string`"
	}
}

func determineRequired(tag TagInfo) string {
	v := tag.Validate
	if v == "" {
		return "No"
	}

	// Split validation rules on comma, stopping at "dive" (everything after
	// dive applies to collection elements, not the field itself).
	var rules []string
	for r := range strings.SplitSeq(v, ",") {
		r = strings.TrimSpace(r)
		if r == "dive" {
			break
		}
		rules = append(rules, r)
	}

	reExcluded := regexp.MustCompile(`excluded_with=(\w+)`)

	for _, r := range rules {
		// required_if=Field value [Field2 value2 ...]
		if after, ok := strings.CutPrefix(r, "required_if="); ok {
			parts := strings.Fields(after)
			var conditions []string
			for i := 0; i+1 < len(parts); i += 2 {
				field := camelToSnake(parts[i])
				val := parts[i+1]
				if field == "enable" && val == "true" {
					conditions = append(conditions, "enabled")
				} else {
					conditions = append(conditions, fmt.Sprintf("%s is \"%s\"", field, val))
				}
			}
			cond := strings.Join(conditions, " and ")
			if tag.Default != "" {
				return "No"
			}
			if m := reExcluded.FindStringSubmatch(v); len(m) > 1 {
				return fmt.Sprintf("Yes (if %s; mutually exclusive with %s)", cond, camelToSnake(m[1]))
			}
			return fmt.Sprintf("Yes (if %s)", cond)
		}

		// required_without_all=Field1 Field2 ...
		if after, ok := strings.CutPrefix(r, "required_without_all="); ok {
			parts := strings.Fields(after)
			names := make([]string, len(parts))
			for i, p := range parts {
				names[i] = camelToSnake(p)
			}
			return fmt.Sprintf("Yes (if none of %s set)", strings.Join(names, ", "))
		}

		// required_without=Field
		if after, ok := strings.CutPrefix(r, "required_without="); ok {
			parts := strings.Fields(after)
			if len(parts) > 0 {
				field := camelToSnake(parts[0])
				if m := reExcluded.FindStringSubmatch(v); len(m) > 1 {
					return fmt.Sprintf("Yes (if %s not set; mutually exclusive)", field)
				}
				return fmt.Sprintf("Yes (if %s not set)", field)
			}
		}

		// required_with=Field
		if after, ok := strings.CutPrefix(r, "required_with="); ok {
			parts := strings.Fields(after)
			if len(parts) > 0 {
				field := camelToSnake(parts[0])
				if tag.Default != "" {
					return "No"
				}
				return fmt.Sprintf("Yes (if %s set)", field)
			}
		}

		// required_unless=Field value [Field2 value2 ...]
		if after, ok := strings.CutPrefix(r, "required_unless="); ok {
			parts := strings.Fields(after)
			var conditions []string
			for i := 0; i+1 < len(parts); i += 2 {
				field := camelToSnake(parts[i])
				val := parts[i+1]
				conditions = append(conditions, fmt.Sprintf("%s is \"%s\"", field, val))
			}
			return fmt.Sprintf("Yes (unless %s)", strings.Join(conditions, " or "))
		}

		// bare required
		if r == "required" {
			if tag.Default != "" {
				return "No"
			}
			return "Yes"
		}
	}

	// Standalone excluded_with without a required_* tag
	if m := reExcluded.FindStringSubmatch(v); len(m) > 1 {
		return fmt.Sprintf("No (mutually exclusive with %s)", camelToSnake(m[1]))
	}
	return "No"
}

// parseDocConstraints reads a Go source file and extracts structured
// "// doc:constraint" comments. Format:
//
//	// doc:constraint name="<id>" struct="<GoType>" applies="<Field1>,<Field2>" description="<text>"
func parseDocConstraints(path string) ([]DocConstraint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`//\s*doc:constraint\s+(.+)`)
	kvRe := regexp.MustCompile(`(\w+)="([^"]*)"`)
	var constraints []DocConstraint
	for line := range strings.SplitSeq(string(data), "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		kvs := kvRe.FindAllStringSubmatch(m[1], -1)
		c := DocConstraint{}
		for _, kv := range kvs {
			switch kv[1] {
			case "name":
				c.Name = kv[2]
			case "struct":
				c.Struct = kv[2]
			case "applies":
				c.Applies = strings.Split(kv[2], ",")
			case "description":
				c.Description = kv[2]
			}
		}
		if c.Name != "" && c.Struct != "" {
			constraints = append(constraints, c)
		}
	}
	return constraints, nil
}

// buildConstraintsByType groups constraints by struct name for inline rendering.
func buildConstraintsByType(constraints []DocConstraint) map[string][]DocConstraint {
	idx := make(map[string][]DocConstraint)
	for _, c := range constraints {
		idx[c.Struct] = append(idx[c.Struct], c)
	}
	return idx
}

func formatDefault(tag TagInfo) string {
	if tag.Default == "" {
		return "-"
	}
	d := strings.ReplaceAll(tag.Default, `\"`, `"`)
	return "`" + d + "`"
}

func formatExample(example string) string {
	if example == "" {
		return "-"
	}
	return "`" + example + "`"
}

func fieldDescription(f *FieldDef) string {
	raw := f.Doc
	if raw == "" {
		raw = f.InlineDoc
	}
	if raw == "" {
		return titleFromGoName(f.GoName)
	}
	var parts []string
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			parts = append(parts, line)
		}
	}
	if len(parts) == 0 {
		return titleFromGoName(f.GoName)
	}
	// Clean the first line (strip "FieldName is the ..." prefix), keep the rest as-is
	parts[0] = cleanFieldDesc(parts[0], f.GoName)
	return strings.Join(parts, " ")
}

// fieldExample returns the doc_example tag value for a field.
func fieldExample(f *FieldDef) string {
	return f.Tag.DocExample
}

func cleanFieldDesc(line, goName string) string {
	prefixes := []string{
		goName + " is the ",
		goName + " is a ",
		goName + " is an ",
		goName + " is ",
		goName + " are the ",
		goName + " are ",
		goName + " holds the ",
		goName + " holds ",
		goName + " defines ",
		goName + " states ",
		goName + " turns on ",
		goName + " controls ",
		goName + " allows ",
		goName + " provides ",
		goName + " specifies ",
		goName + " configures ",
		goName + " maps ",
		goName + " forces ",
		goName + " displays ",
		goName + " toggles ",
		goName + " lists ",
		goName + " enables ",
		goName + " sets ",
	}
	for _, p := range prefixes {
		if after, ok := strings.CutPrefix(line, p); ok {
			rest := after
			if len(rest) > 0 {
				return strings.ToUpper(rest[:1]) + rest[1:]
			}
			return rest
		}
	}
	return line
}

// fenceEdge handles a ``` line and the blank lines gofmt insists on putting
// just inside it. Those blanks are the Go comment's punctuation, not the
// example's, so they are dropped rather than rendered inside the block.
func fenceEdge(extra []string, opening bool) []string {
	if !opening && len(extra) > 0 && extra[len(extra)-1] == "" {
		extra = extra[:len(extra)-1]
	}
	return extra
}

// structDescription renders a struct's doc comment as the section preamble.
//
// Lines reflow as markdown, EXCEPT inside a ``` fenced block, where the
// indentation is the content - a YAML example flattened to column zero is not
// an example of anything. See IssuancePolicy, whose policy has to be shown as
// rules and query_template together to be a configuration at all.
func structDescription(def *StructDef) string {
	if def == nil || def.Doc == "" {
		return ""
	}
	lines := strings.Split(def.Doc, "\n")
	first := strings.TrimSpace(lines[0])
	cleaned := cleanFieldDesc(first, def.Name)
	if cleaned == "" {
		return ""
	}
	cleaned = strings.ToUpper(cleaned[:1]) + cleaned[1:]
	if !strings.HasSuffix(cleaned, ".") {
		cleaned += "."
	}
	var extra []string
	pastBlank := false
	inFence, skipBlank := false, false
	for _, raw := range lines[1:] {
		l := strings.TrimSpace(raw)
		// Inside a fenced block the indentation IS the content, so the
		// line is taken as written. Go doc comments indent an example by
		// one tab; that tab is the comment's, not the example's.
		if strings.HasPrefix(l, "```") {
			inFence = !inFence
			pastBlank = true
			extra = append(fenceEdge(extra, inFence), l)
			skipBlank = inFence
			continue
		}
		if inFence {
			if skipBlank && l == "" {
				continue
			}
			skipBlank = false
			extra = append(extra, strings.TrimPrefix(raw, "\t"))
			continue
		}
		if l == "" {
			pastBlank = true
			if len(extra) > 0 {
				extra = append(extra, "")
			}
			continue
		}
		if pastBlank || len(extra) > 0 {
			extra = append(extra, l)
		}
	}
	if len(extra) > 0 {
		cleaned += "\n\n" + strings.Join(extra, "\n")
	}
	return cleaned
}

func structDescriptionExtra(def *StructDef) string {
	if def == nil || def.Doc == "" {
		return ""
	}
	lines := strings.Split(def.Doc, "\n")
	if len(lines) <= 1 {
		return ""
	}
	var extra []string
	inFence, skipBlank := false, false
	for _, raw := range lines[1:] {
		l := strings.TrimSpace(raw)
		if strings.HasPrefix(l, "```") {
			inFence = !inFence
			extra = append(fenceEdge(extra, inFence), l)
			skipBlank = inFence
			continue
		}
		if inFence {
			if skipBlank && l == "" {
				continue
			}
			skipBlank = false
			extra = append(extra, strings.TrimPrefix(raw, "\t"))
			continue
		}
		if l == "" {
			if len(extra) > 0 {
				extra = append(extra, "")
			}
			continue
		}
		extra = append(extra, l)
	}
	return strings.TrimSpace(strings.Join(extra, "\n"))
}

// knownTerms maps Go identifier fragments to their desired snake_case output.
// Longer keys must come first to ensure greedy matching.
// This handles acronyms (JWKS, URL), digit-containing terms (PKCS11, VCTM),
// and consecutive acronym sequences (JWKSURL → jwks_url).
var knownTerms = []struct {
	match string
	snake string
}{
	{"MariaDB", "mariadb"},
	{"PKCS11", "pkcs11"},
	{"JWKS", "jwks"},
	{"OIDC", "oidc"},
	{"SAML", "saml"},
	{"GRPC", "grpc"},
	{"HTTP", "http"},
	{"VCTM", "vctm"},
	{"URL", "url"},
	{"URI", "uri"},
	{"TLS", "tls"},
	{"PKI", "pki"},
	{"CSS", "css"},
	{"JWT", "jwt"},
}

func camelToSnake(s string) string {
	// Split input into segments: known terms (output directly) and gaps (delegate to strcase).
	type segment struct {
		text   string
		isTerm bool
	}

	var segments []segment
	i := 0
	for i < len(s) {
		matched := false
		for _, t := range knownTerms {
			if strings.HasPrefix(s[i:], t.match) {
				segments = append(segments, segment{text: t.snake, isTerm: true})
				i += len(t.match)
				matched = true
				break
			}
		}
		if !matched {
			// Accumulate non-term characters into a gap
			if len(segments) > 0 && !segments[len(segments)-1].isTerm {
				segments[len(segments)-1].text += string(s[i])
			} else {
				segments = append(segments, segment{text: string(s[i]), isTerm: false})
			}
			i++
		}
	}

	// Build result: convert gaps with strcase, join all with underscores
	var parts []string
	for _, seg := range segments {
		if seg.isTerm {
			parts = append(parts, seg.text)
		} else {
			converted := strcase.ToSnake(seg.text)
			parts = append(parts, converted)
		}
	}

	return strings.Join(parts, "_")
}

func titleFromGoName(name string) string {
	// Handle common acronyms that shouldn't be split
	runes := []rune(name)
	var words []string
	start := 0
	for i := 1; i < len(runes); i++ {
		if unicode.IsUpper(runes[i]) {
			if !unicode.IsUpper(runes[i-1]) {
				// Transition lower->upper: split before current
				words = append(words, string(runes[start:i]))
				start = i
			} else if i+1 < len(runes) && !unicode.IsUpper(runes[i+1]) {
				// Transition UPPER->Xxxxx: split before current
				words = append(words, string(runes[start:i]))
				start = i
			}
		}
	}
	if start < len(runes) {
		words = append(words, string(runes[start:]))
	}
	// Join with spaces, keeping acronyms like URI, QR, TLS intact
	var parts []string
	for _, w := range words {
		if w == "" {
			continue
		}
		parts = append(parts, w)
	}
	return strings.Join(parts, " ")
}

func anchor(heading string) string {
	s := strings.ToLower(heading)
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return '-'
		}
		if r == '_' {
			return '_'
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
			return r
		}
		return -1
	}, s)
	return strings.TrimRight(s, "-")
}

// ---- Document builder ----

var documented = map[string]bool{}

// subsByType maps Go type names to the first SubSection that documented them,
// so additional paths can be appended.
var subsByType = map[string]*SubSection{}

// constraintsByType maps Go struct name to its doc constraints (for inline rendering).
var constraintsByType map[string][]DocConstraint

func buildDocument(reg *TypeRegistry) []*DocSection {
	cfg := reg.Lookup("Cfg")
	if cfg == nil {
		log.Fatal("Cfg struct not found in type registry")
	}
	var sections []*DocSection
	for _, field := range cfg.Fields {
		if field.Tag.YAMLName == "" || field.Tag.YAMLName == "-" {
			continue
		}
		sec := buildTopLevel(reg, field, cfg.PkgName)
		if sec != nil {
			sections = append(sections, sec)
		}
	}

	// Add secrets file section
	if sec := buildSecretsSection(reg); sec != nil {
		sections = append(sections, sec)
	}

	// Derivation primitives section, rendered by walking the fields of
	// pkg/credential/primitives.Derivation (the single source of truth).
	if sec := buildPrimitivesSection(reg); sec != nil {
		sections = append(sections, sec)
	}

	return sections
}

// buildPrimitivesSection renders the "Derivation Primitives" catalog by
// walking the fields of pkg/credential/primitives.Derivation as parsed into
// the type registry. Each pointer field names a primitive (via its yaml
// tag); the pointed-at Args struct supplies the parameter table and its
// doc comment supplies the summary.
func buildPrimitivesSection(reg *TypeRegistry) *DocSection {
	d := reg.Lookup("Derivation")
	if d == nil {
		return nil
	}
	sec := &DocSection{
		YAMLKey:     "primitives",
		Title:       "Derivation Primitives",
		Description: structDescription(d),
	}
	for _, f := range d.Fields {
		if f.Tag.YAMLName == "" || f.Tag.YAMLName == "-" {
			continue
		}
		argsName := resolveTypeName(f.TypeExpr)
		if argsName == "" {
			continue
		}
		argsDef := reg.Lookup(argsName)
		if argsDef == nil {
			continue
		}
		sub := buildStructSubSection(reg, argsDef, fmt.Sprintf("<scope>.derivations[].%s", f.Tag.YAMLName))
		sub.Title = f.Tag.YAMLName
		if desc := fieldDescription(f); desc != "" {
			sub.Desc = desc
		}
		sec.Subs = append(sec.Subs, sub)
	}
	return sec
}

func buildSecretsSection(reg *TypeRegistry) *DocSection {
	secrets := reg.Lookup("Secrets")
	if secrets == nil {
		return nil
	}

	sec := &DocSection{
		YAMLKey:     "secrets_file",
		Title:       "Secrets File Reference",
		Description: structDescription(secrets),
	}

	// Build the top-level secrets struct table
	mainSub := buildStructSubSection(reg, secrets, "(root)")
	mainSub.Title = "Secrets file structure"
	sec.Subs = append(sec.Subs, mainSub)
	if secrets.Name != "" {
		documented[secrets.PkgName+"."+secrets.Name] = true
	}

	// Expand all child structs
	expandChildren(reg, secrets, "", &sec.Subs)

	// Generate a YAML example
	example := generateSecretsExample(reg, secrets, 0)
	exampleSub := &SubSection{
		Title: "Example `secrets.yaml`",
		Path:  "file referenced by .common.secret_file_path",
	}
	exampleSub.Desc = "```yaml\n" + example + "```"
	sec.Subs = append(sec.Subs, exampleSub)

	return sec
}

// generateSecretsExample generates a YAML example from the Secrets struct tree.
func generateSecretsExample(reg *TypeRegistry, def *StructDef, indent int) string {
	var buf strings.Builder
	prefix := strings.Repeat("  ", indent)
	for _, f := range def.Fields {
		if f.Tag.YAMLName == "" || f.Tag.YAMLName == "-" {
			continue
		}
		typeName := resolveTypeName(f.TypeExpr)
		childDef := reg.Lookup(typeName)

		if childDef != nil && len(childDef.Fields) > 0 {
			buf.WriteString(fmt.Sprintf("%s%s:\n", prefix, f.Tag.YAMLName))
			buf.WriteString(generateSecretsExample(reg, childDef, indent+1))
		} else if _, ok := asMapType(f.TypeExpr); ok {
			buf.WriteString(fmt.Sprintf("%s%s:\n", prefix, f.Tag.YAMLName))
			if f.Tag.DocExample != "" {
				buf.WriteString(fmt.Sprintf("%s  %s\n", prefix, f.Tag.DocExample))
			} else {
				keyPH := mapKeyPlaceholder(f.Tag)
				buf.WriteString(fmt.Sprintf("%s  %s: \"<value>\"\n", prefix, keyPH))
			}
		} else {
			placeholder := secretPlaceholder(f.Tag.YAMLName)
			buf.WriteString(fmt.Sprintf("%s%s: %s\n", prefix, f.Tag.YAMLName, placeholder))
		}
	}
	return buf.String()
}

func secretPlaceholder(yamlName string) string {
	// Placeholders for secrets file documentation examples.
	// These are NOT real credentials — they are shown as fill-in templates.
	placeholders := map[string]string{ //#nosec G101 -- documentation placeholders, not real credentials
		"uri":                               "\"mongodb://mongo:27017/vc\"",
		"client_secret":                     "\"your-oidc-client-secret\"",
		"password":                          "\"change-me-in-production\"",
		"session_secret":                    "\"random-32-byte-secret\"",
		"subject_salt":                      "\"random-salt-for-pairwise-subjects\"",
		"session_cookie_authentication_key": "\"64-char-hex-hmac-key\"",
		"session_store_encryption_key":      "\"32-char-hex-encryption-key\"",
	}
	if p, ok := placeholders[yamlName]; ok {
		return p
	}
	return "\"<secret-value>\""
}

func buildTopLevel(reg *TypeRegistry, field *FieldDef, pkgName string) *DocSection {
	yamlKey := field.Tag.YAMLName

	var def *StructDef
	typeName := resolveTypeName(field.TypeExpr)
	if typeName != "" {
		def = reg.LookupInPkg(typeName, pkgName)
	}
	if def == nil && field.InlineDef != nil {
		def = field.InlineDef
	}

	isMap := false
	var mapValDef *StructDef
	if mt, ok := asMapType(field.TypeExpr); ok {
		isMap = true
		valName := resolveTypeName(mt.Value)
		if valName != "" {
			mapValDef = reg.LookupInPkg(valName, pkgName)
		}
	}

	sec := &DocSection{
		YAMLKey: yamlKey,
		Title:   fmt.Sprintf("`%s` (Top-level)", yamlKey),
	}

	if isMap && mapValDef != nil {
		keyPH := mapKeyPlaceholder(field.Tag)
		sec.Description = structDescription(mapValDef)
		sub := buildStructSubSection(reg, mapValDef, fmt.Sprintf(".%s.%s", yamlKey, keyPH))
		sub.Title = fmt.Sprintf("`%s`", yamlKey)
		sec.Subs = append(sec.Subs, sub)
		if mapValDef.Name != "" {
			documented[mapValDef.PkgName+"."+mapValDef.Name] = true
		}
		expandChildren(reg, mapValDef, fmt.Sprintf(".%s.%s", yamlKey, keyPH), &sec.Subs)
	} else if def != nil {
		sec.Description = structDescription(def)
		mainSub := buildStructSubSection(reg, def, "."+yamlKey)
		mainSub.Title = fmt.Sprintf("`%s`", yamlKey)
		sec.Subs = append(sec.Subs, mainSub)
		if def.Name != "" {
			documented[def.PkgName+"."+def.Name] = true
		}
		expandChildren(reg, def, "."+yamlKey, &sec.Subs)
	} else {
		return nil
	}

	return sec
}

func asMapType(expr ast.Expr) (*ast.MapType, bool) {
	switch t := expr.(type) {
	case *ast.MapType:
		return t, true
	case *ast.StarExpr:
		return asMapType(t.X)
	default:
		return nil, false
	}
}

func buildStructSubSection(reg *TypeRegistry, def *StructDef, path string) *SubSection {
	sub := &SubSection{Path: path, TypeName: def.Name}

	desc := structDescriptionExtra(def)
	if desc != "" {
		sub.Desc = desc
	}

	for _, f := range def.Fields {
		if f.Tag.YAMLName == "" || f.Tag.YAMLName == "-" {
			continue
		}
		// Primitive Args structs always pair `input` with an `output` that
		// mirrors it; the description covers the semantics, so skip the row.
		if def.PkgName == "primitives" && f.Tag.YAMLName == "output" {
			continue
		}
		row := TableRow{
			Field:    "`" + f.Tag.YAMLName + "`",
			Type:     reg.displayType(f.TypeExpr),
			Desc:     fieldDescription(f),
			Example:  formatExample(fieldExample(f)),
			Default:  formatDefault(f.Tag),
			Required: determineRequired(f.Tag),
		}
		sub.Rows = append(sub.Rows, row)
	}

	// Append inline constraint notes for this struct type (before the table)
	if cs, ok := constraintsByType[def.Name]; ok {
		var notes strings.Builder
		for i, c := range cs {
			if i > 0 {
				notes.WriteString(">\n")
			}
			fields := make([]string, len(c.Applies))
			for j, f := range c.Applies {
				fields[j] = "`" + camelToSnake(strings.TrimSpace(f)) + "`"
			}
			notes.WriteString(fmt.Sprintf("> **Constraint** (%s): %s\n", strings.Join(fields, ", "), c.Description))
		}
		if sub.Desc != "" {
			sub.Desc = notes.String() + "\n" + sub.Desc
		} else {
			sub.Desc = notes.String()
		}
	}

	// Track this subsection by package-qualified type name for merging
	// additional paths. Simple name alone collides between unrelated
	// packages (e.g. pubsub.Config vs openidfederation.Config), which
	// then merges their fields and paths into one section.
	if def.Name != "" {
		key := def.PkgName + "." + def.Name
		if existing, ok := subsByType[key]; ok {
			existing.AlsoPaths = append(existing.AlsoPaths, path)
		} else {
			subsByType[key] = sub
		}
	}

	return sub
}

func expandChildren(reg *TypeRegistry, def *StructDef, parentPath string, subs *[]*SubSection) {
	for _, f := range def.Fields {
		if f.Tag.YAMLName == "" || f.Tag.YAMLName == "-" {
			continue
		}
		childPath := parentPath + "." + f.Tag.YAMLName
		expanded := false

		// Named struct type
		typeName := resolveTypeName(f.TypeExpr)
		if typeName != "" {
			if childDef := reg.LookupInPkg(typeName, def.PkgName); childDef != nil {
				qName := childDef.PkgName + "." + childDef.Name
				if !documented[qName] {
					documented[qName] = true
					sub := buildStructSubSection(reg, childDef, childPath)
					sub.Title = fmt.Sprintf("`%s`", f.Tag.YAMLName)
					*subs = append(*subs, sub)
					expandChildren(reg, childDef, childPath, subs)
				} else {
					// Type already documented; record this additional path
					recordAdditionalPath(childDef, childPath)
					recordChildPaths(reg, childDef, childPath)
				}
				expanded = true
			}
		}

		// Named map type alias (e.g., type Clients map[string]*Client)
		if !expanded && typeName != "" {
			if valDef := reg.LookupMapValueTypeInPkg(typeName, def.PkgName); valDef != nil {
				keyPH := mapKeyPlaceholder(f.Tag)
				qName := valDef.PkgName + "." + valDef.Name
				if !documented[qName] {
					documented[qName] = true
					sub := buildStructSubSection(reg, valDef, childPath+"."+keyPH)
					sub.Title = fmt.Sprintf("`%s` entry", f.Tag.YAMLName)
					*subs = append(*subs, sub)
					expandChildren(reg, valDef, childPath+"."+keyPH, subs)
				} else {
					recordAdditionalPath(valDef, childPath+"."+keyPH)
					recordChildPaths(reg, valDef, childPath+"."+keyPH)
				}
				expanded = true
			}
		}

		// Inline struct
		if !expanded && f.InlineDef != nil {
			sub := buildStructSubSection(reg, f.InlineDef, childPath)
			sub.Title = fmt.Sprintf("`%s`", f.Tag.YAMLName)
			*subs = append(*subs, sub)
			expandChildren(reg, f.InlineDef, childPath, subs)
			expanded = true
		}

		// Map with struct value (or nested map alias value)
		if !expanded {
			if mt, ok := asMapType(f.TypeExpr); ok {
				valName := resolveTypeName(mt.Value)
				if valName != "" {
					valDef := reg.LookupInPkg(valName, def.PkgName)
					keyPH := mapKeyPlaceholder(f.Tag)
					// If the map value is itself a named map alias, resolve one level deeper
					if valDef == nil {
						if innerDef := reg.LookupMapValueTypeInPkg(valName, def.PkgName); innerDef != nil {
							valDef = innerDef
							innerKey := "<key>"
							if f.Tag.DocValueKey != "" {
								innerKey = "<" + f.Tag.DocValueKey + ">"
							}
							keyPH = keyPH + "." + innerKey
						}
					}
					if valDef != nil {
						qName := valDef.PkgName + "." + valDef.Name
						if !documented[qName] {
							documented[qName] = true
							sub := buildStructSubSection(reg, valDef, childPath+"."+keyPH)
							sub.Title = fmt.Sprintf("`%s` entry", f.Tag.YAMLName)
							*subs = append(*subs, sub)
							expandChildren(reg, valDef, childPath+"."+keyPH, subs)
						} else {
							recordAdditionalPath(valDef, childPath+"."+keyPH)
							recordChildPaths(reg, valDef, childPath+"."+keyPH)
						}
					}
				}
			}
		}

		// Slice of structs
		if !expanded {
			if at, ok := f.TypeExpr.(*ast.ArrayType); ok {
				elemName := resolveTypeName(at.Elt)
				if elemName != "" {
					if elemDef := reg.LookupInPkg(elemName, def.PkgName); elemDef != nil {
						qName := elemDef.PkgName + "." + elemDef.Name
						if !documented[qName] {
							documented[qName] = true
							sub := buildStructSubSection(reg, elemDef, childPath+"[]")
							sub.Title = fmt.Sprintf("`%s` entry", f.Tag.YAMLName)
							*subs = append(*subs, sub)
							expandChildren(reg, elemDef, childPath+"[]", subs)
						} else {
							recordAdditionalPath(elemDef, childPath+"[]")
							recordChildPaths(reg, elemDef, childPath+"[]")
						}
					}
				}
			}
		}
	}
}

func recordAdditionalPath(def *StructDef, path string) {
	if def == nil {
		return
	}
	if sub, ok := subsByType[def.PkgName+"."+def.Name]; ok {
		sub.AlsoPaths = append(sub.AlsoPaths, path)
	}
}

// recordChildPaths recursively records additional paths for all children of an
// already-documented struct. This ensures that when the same struct type appears
// under multiple parents (e.g., OAuthServer under both apigw and verifier),
// child types (e.g., Client under Clients) also get their additional paths recorded.
//
// Named lookups use the package-aware LookupInPkg variants so that children
// whose simple name is ambiguous (Config, Client, ...) resolve against
// def.PkgName instead of being silently dropped by the nil-sentinel entry
// extractStructs installs for cross-package collisions.
func recordChildPaths(reg *TypeRegistry, def *StructDef, parentPath string) {
	for _, f := range def.Fields {
		if f.Tag.YAMLName == "" || f.Tag.YAMLName == "-" {
			continue
		}
		childPath := parentPath + "." + f.Tag.YAMLName
		recorded := false

		// Named struct type
		typeName := resolveTypeName(f.TypeExpr)
		if typeName != "" {
			if childDef := reg.LookupInPkg(typeName, def.PkgName); childDef != nil {
				recordAdditionalPath(childDef, childPath)
				recordChildPaths(reg, childDef, childPath)
				recorded = true
			}
		}

		// Named map type alias
		if !recorded && typeName != "" {
			if valDef := reg.LookupMapValueTypeInPkg(typeName, def.PkgName); valDef != nil {
				keyPH := mapKeyPlaceholder(f.Tag)
				recordAdditionalPath(valDef, childPath+"."+keyPH)
				recordChildPaths(reg, valDef, childPath+"."+keyPH)
				recorded = true
			}
		}

		// Map with struct value
		if !recorded {
			if mt, ok := asMapType(f.TypeExpr); ok {
				valName := resolveTypeName(mt.Value)
				if valName != "" {
					if valDef := reg.LookupInPkg(valName, def.PkgName); valDef != nil {
						keyPH := mapKeyPlaceholder(f.Tag)
						recordAdditionalPath(valDef, childPath+"."+keyPH)
						recordChildPaths(reg, valDef, childPath+"."+keyPH)
					}
				}
			}
		}

		// Slice of structs
		if !recorded {
			if at, ok := f.TypeExpr.(*ast.ArrayType); ok {
				elemName := resolveTypeName(at.Elt)
				if elemName != "" {
					if elemDef := reg.LookupInPkg(elemName, def.PkgName); elemDef != nil {
						recordAdditionalPath(elemDef, childPath+"[]")
						recordChildPaths(reg, elemDef, childPath+"[]")
					}
				}
			}
		}
	}
}

// ---- Markdown rendering ----

func renderDocument(sections []*DocSection) string {
	var buf strings.Builder

	buf.WriteString("# Configuration Reference\n\n")
	buf.WriteString("Complete reference for all configuration parameters in the VC system.\n\n")
	buf.WriteString("<!-- Auto-generated from Go source code. DO NOT EDIT MANUALLY. -->\n")
	buf.WriteString("<!-- Regenerate with: go run developer_tools/scripts/gen_config_docs/main.go -->\n\n")

	// TOC
	buf.WriteString("## Table of Contents\n\n")
	buf.WriteString("- [Environment Variables](#environment-variables)\n")
	for _, sec := range sections {
		label := sectionLabel(sec.YAMLKey)
		buf.WriteString(fmt.Sprintf("- [%s](#%s)\n", label, anchor(sec.Title)))
	}
	buf.WriteString("\n")

	// Environment Variables section
	buf.WriteString("## Environment Variables\n\n")
	buf.WriteString("These environment variables control service behavior outside of the YAML configuration file.\n\n")
	envVars := []struct{ Var, Desc, Example string }{
		{"`VC_CONFIG_YAML`", "Path to the YAML configuration file. Each service reads this on startup.", "`config.yaml`"},
		{"`SSL_CERT_FILE`", "Path to a CA certificate file that Go's `crypto/x509` trusts for TLS verification. Required when services use self-signed or private CA certificates for inter-service HTTPS.", "`/pki/rootCA.crt`"},
	}
	envWidths := [3]int{len("Variable"), len("Description"), len("Example")}
	for _, e := range envVars {
		if len(e.Var) > envWidths[0] {
			envWidths[0] = len(e.Var)
		}
		if len(e.Desc) > envWidths[1] {
			envWidths[1] = len(e.Desc)
		}
		if len(e.Example) > envWidths[2] {
			envWidths[2] = len(e.Example)
		}
	}
	buf.WriteString(fmt.Sprintf("| %-*s | %-*s | %-*s |\n", envWidths[0], "Variable", envWidths[1], "Description", envWidths[2], "Example"))
	buf.WriteString(fmt.Sprintf("| %s | %s | %s |\n", strings.Repeat("-", envWidths[0]), strings.Repeat("-", envWidths[1]), strings.Repeat("-", envWidths[2])))
	for _, e := range envVars {
		buf.WriteString(fmt.Sprintf("| %-*s | %-*s | %-*s |\n", envWidths[0], e.Var, envWidths[1], e.Desc, envWidths[2], e.Example))
	}
	buf.WriteString("\n")

	for _, sec := range sections {
		renderSection(&buf, sec)
	}

	return buf.String()
}

func sectionLabel(yamlKey string) string {
	labels := map[string]string{ //#nosec G101 -- section labels, not credentials
		"common":       "Common",
		"apigw":        "API Gateway (APIGW)",
		"issuer":       "Issuer",
		"verifier":     "Verifier",
		"registry":     "Registry",
		"secrets_file": "Secrets File Reference",
		"primitives":   "Derivation Primitives",
	}
	if l, ok := labels[yamlKey]; ok {
		return l
	}
	return strings.ReplaceAll(yamlKey, "_", " ")
}

func renderSection(buf *strings.Builder, sec *DocSection) {
	buf.WriteString(fmt.Sprintf("## %s\n\n", sec.Title))
	if sec.Description != "" {
		buf.WriteString(sec.Description + "\n\n")
	}
	for _, sub := range sec.Subs {
		renderSubSection(buf, sub)
	}
}

func renderSubSection(buf *strings.Builder, sub *SubSection) {
	buf.WriteString(fmt.Sprintf("### %s\n\n", sub.Title))
	if len(sub.AlsoPaths) > 0 {
		allPaths := make([]string, 0, 1+len(sub.AlsoPaths))
		allPaths = append(allPaths, "`"+sub.Path+"`")
		for _, p := range sub.AlsoPaths {
			allPaths = append(allPaths, "`"+p+"`")
		}
		buf.WriteString(fmt.Sprintf("> **Path:** %s\n\n", strings.Join(allPaths, ", ")))
	} else {
		buf.WriteString(fmt.Sprintf("> **Path:** `%s`\n\n", sub.Path))
	}
	if sub.Desc != "" {
		// Ensure description ends with a blank line before the table
		desc := strings.TrimSpace(sub.Desc)
		buf.WriteString(desc + "\n\n")
	}
	if len(sub.Rows) > 0 {
		renderTable(buf, sub.Rows)
	}
	if sub.AfterText != "" {
		buf.WriteString("\n" + sub.AfterText + "\n")
	}
	buf.WriteString("\n")
}

func renderTable(buf *strings.Builder, rows []TableRow) {
	headers := TableRow{
		Field: "Field", Type: "Type", Desc: "Description",
		Example: "Example", Default: "Default", Required: "Required",
	}
	widths := [6]int{
		len(headers.Field), len(headers.Type), len(headers.Desc),
		len(headers.Example), len(headers.Default), len(headers.Required),
	}
	for _, r := range rows {
		if len(r.Field) > widths[0] {
			widths[0] = len(r.Field)
		}
		if len(r.Type) > widths[1] {
			widths[1] = len(r.Type)
		}
		if len(r.Desc) > widths[2] {
			widths[2] = len(r.Desc)
		}
		if len(r.Example) > widths[3] {
			widths[3] = len(r.Example)
		}
		if len(r.Default) > widths[4] {
			widths[4] = len(r.Default)
		}
		if len(r.Required) > widths[5] {
			widths[5] = len(r.Required)
		}
	}

	writeRow := func(r TableRow) {
		buf.WriteString(fmt.Sprintf("| %-*s | %-*s | %-*s | %-*s | %-*s | %-*s |\n",
			widths[0], r.Field,
			widths[1], r.Type,
			widths[2], r.Desc,
			widths[3], r.Example,
			widths[4], r.Default,
			widths[5], r.Required))
	}
	writeSep := func() {
		buf.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			strings.Repeat("-", widths[0]),
			strings.Repeat("-", widths[1]),
			strings.Repeat("-", widths[2]),
			strings.Repeat("-", widths[3]),
			strings.Repeat("-", widths[4]),
			strings.Repeat("-", widths[5])))
	}

	writeRow(headers)
	writeSep()
	for _, r := range rows {
		writeRow(r)
	}
}

// ---- Main ----

func main() {
	rootFlag := flag.String("root", "", "workspace root (auto-detected if empty)")
	outFlag := flag.String("out", "docs/CONFIGURATION.md", "output path relative to root")
	flag.Parse()

	root := *rootFlag
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatalf("cannot get working directory: %v", err)
		}
		root = wd
	}

	reg := NewTypeRegistry()
	dirs := []string{
		filepath.Join(root, "pkg/model"),
		filepath.Join(root, "pkg/pki"),
		filepath.Join(root, "pkg/oauth2"),
		filepath.Join(root, "pkg/openid4vp"),
		filepath.Join(root, "pkg/openid4vci"),
		filepath.Join(root, "pkg/openidfederation"),
		filepath.Join(root, "pkg/pubsub"),
		filepath.Join(root, "pkg/sqlstore"),
		filepath.Join(root, "pkg/credential/primitives"),
	}
	for _, d := range dirs {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			continue
		}
		if err := reg.ParseDir(d); err != nil {
			log.Fatalf("error parsing %s: %v", d, err)
		}
	}

	// Parse doc:constraint comments from validate.go
	validatePath := filepath.Join(root, "pkg/helpers/validate.go")
	if _, err := os.Stat(validatePath); err == nil {
		parsed, err := parseDocConstraints(validatePath)
		if err != nil {
			log.Fatalf("parsing doc constraints: %v", err)
		}
		constraintsByType = buildConstraintsByType(parsed)
	}

	sections := buildDocument(reg)
	markdown := renderDocument(sections)

	outPath := filepath.Join(root, *outFlag)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		log.Fatalf("creating output dir: %v", err)
	}
	if err := os.WriteFile(outPath, []byte(markdown), 0o600); err != nil {
		log.Fatalf("writing %s: %v", outPath, err)
	}
	fmt.Printf("Generated %s (%d bytes)\n", outPath, len(markdown))
}
