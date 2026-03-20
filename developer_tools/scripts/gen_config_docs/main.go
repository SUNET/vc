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
	"time"
	"unicode"
)

// ---- Data types ----

type TagInfo struct {
	YAMLName   string
	Omitempty  bool
	Validate   string
	Default    string
	DocExample string
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
	types      map[string]*StructDef
	mapAliases map[string]string // named map type -> map value type name
	fset       *token.FileSet
}

func NewTypeRegistry() *TypeRegistry {
	return &TypeRegistry{
		types:      make(map[string]*StructDef),
		mapAliases: make(map[string]string),
		fset:       token.NewFileSet(),
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
				r.types[ts.Name.Name] = def
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
		return t.Sel.Name
	default:
		return ""
	}
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
	return TagInfo{YAMLName: yamlName, Omitempty: omit, Validate: validate, Default: def, DocExample: docExample}
}

// ---- Display helpers ----

func displayType(expr ast.Expr) string {
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
			return "`object`"
		}
	case *ast.StarExpr:
		return displayType(t.X)
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
	if strings.Contains(v, "required_if=Enable true") {
		return "Yes (if enabled)"
	}
	re := regexp.MustCompile(`required_without=(\w+)`)
	if m := re.FindStringSubmatch(v); len(m) > 1 {
		return fmt.Sprintf("Yes (if %s not set)", camelToSnake(m[1]))
	}
	for r := range strings.SplitSeq(v, ",") {
		r = strings.TrimSpace(r)
		if r == "required" {
			// If a default value is provided, the field is not required from
			// the end-user's perspective since the default will be used.
			if tag.Default != "" {
				return "No"
			}
			return "Yes"
		}
	}
	return "No"
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
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
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
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
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

func camelToSnake(s string) string {
	runes := []rune(s)
	var b strings.Builder
	for i, r := range runes {
		if unicode.IsUpper(r) && i > 0 {
			// Only insert underscore if previous char is lowercase
			// or if next char is lowercase (end of acronym)
			prevLower := unicode.IsLower(runes[i-1])
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if prevLower || nextLower {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
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
		sec := buildTopLevel(reg, field)
		if sec != nil {
			sections = append(sections, sec)
		}
	}

	// Add secrets file section
	if sec := buildSecretsSection(reg); sec != nil {
		sections = append(sections, sec)
	}

	return sections
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
		documented[secrets.Name] = true
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
				buf.WriteString(fmt.Sprintf("%s  <key>: \"<value>\"\n", prefix))
			}
		} else {
			placeholder := secretPlaceholder(f.Tag.YAMLName)
			buf.WriteString(fmt.Sprintf("%s%s: %s\n", prefix, f.Tag.YAMLName, placeholder))
		}
	}
	return buf.String()
}

func secretPlaceholder(yamlName string) string {
	placeholders := map[string]string{
		"uri":                               "\"mongodb://user:password@mongo:27017/vc\"",
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

func buildTopLevel(reg *TypeRegistry, field *FieldDef) *DocSection {
	yamlKey := field.Tag.YAMLName

	var def *StructDef
	typeName := resolveTypeName(field.TypeExpr)
	if typeName != "" {
		def = reg.Lookup(typeName)
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
			mapValDef = reg.Lookup(valName)
		}
	}

	sec := &DocSection{
		YAMLKey: yamlKey,
		Title:   fmt.Sprintf("`%s` (Top-level)", yamlKey),
	}

	if isMap && mapValDef != nil {
		sec.Description = structDescription(mapValDef)
		sub := buildStructSubSection(reg, mapValDef, fmt.Sprintf(".%s.<key>", yamlKey))
		sub.Title = fmt.Sprintf("`%s`", yamlKey)
		sec.Subs = append(sec.Subs, sub)
		if mapValDef.Name != "" {
			documented[mapValDef.Name] = true
		}
		expandChildren(reg, mapValDef, fmt.Sprintf(".%s.<key>", yamlKey), &sec.Subs)
	} else if def != nil {
		sec.Description = structDescription(def)
		mainSub := buildStructSubSection(reg, def, "."+yamlKey)
		mainSub.Title = fmt.Sprintf("`%s`", yamlKey)
		sec.Subs = append(sec.Subs, mainSub)
		if def.Name != "" {
			documented[def.Name] = true
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
		row := TableRow{
			Field:    "`" + f.Tag.YAMLName + "`",
			Type:     displayType(f.TypeExpr),
			Desc:     fieldDescription(f),
			Example:  formatExample(fieldExample(f)),
			Default:  formatDefault(f.Tag),
			Required: determineRequired(f.Tag),
		}
		sub.Rows = append(sub.Rows, row)
	}

	// Track this subsection by type name for merging additional paths
	if def.Name != "" {
		if existing, ok := subsByType[def.Name]; ok {
			existing.AlsoPaths = append(existing.AlsoPaths, path)
		} else {
			subsByType[def.Name] = sub
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
			if childDef := reg.Lookup(typeName); childDef != nil {
				if !documented[childDef.Name] {
					documented[childDef.Name] = true
					sub := buildStructSubSection(reg, childDef, childPath)
					sub.Title = fmt.Sprintf("`%s`", f.Tag.YAMLName)
					*subs = append(*subs, sub)
					expandChildren(reg, childDef, childPath, subs)
				} else {
					// Type already documented; record this additional path
					recordAdditionalPath(childDef.Name, childPath)
					recordChildPaths(reg, childDef, childPath)
				}
				expanded = true
			}
		}

		// Named map type alias (e.g., type Clients map[string]*Client)
		if !expanded && typeName != "" {
			if valDef := reg.LookupMapValueType(typeName); valDef != nil {
				if !documented[valDef.Name] {
					documented[valDef.Name] = true
					sub := buildStructSubSection(reg, valDef, childPath+".<key>")
					sub.Title = fmt.Sprintf("`%s` entry", f.Tag.YAMLName)
					*subs = append(*subs, sub)
					expandChildren(reg, valDef, childPath+".<key>", subs)
				} else {
					recordAdditionalPath(valDef.Name, childPath+".<key>")
					recordChildPaths(reg, valDef, childPath+".<key>")
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

		// Map with struct value
		if !expanded {
			if mt, ok := asMapType(f.TypeExpr); ok {
				valName := resolveTypeName(mt.Value)
				if valName != "" {
					if valDef := reg.Lookup(valName); valDef != nil {
						if !documented[valDef.Name] {
							documented[valDef.Name] = true
							sub := buildStructSubSection(reg, valDef, childPath+".<key>")
							sub.Title = fmt.Sprintf("`%s` entry", f.Tag.YAMLName)
							*subs = append(*subs, sub)
							expandChildren(reg, valDef, childPath+".<key>", subs)
						} else {
							recordAdditionalPath(valDef.Name, childPath+".<key>")
							recordChildPaths(reg, valDef, childPath+".<key>")
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
					if elemDef := reg.Lookup(elemName); elemDef != nil {
						if !documented[elemDef.Name] {
							documented[elemDef.Name] = true
							sub := buildStructSubSection(reg, elemDef, childPath+"[]")
							sub.Title = fmt.Sprintf("`%s` entry", f.Tag.YAMLName)
							*subs = append(*subs, sub)
							expandChildren(reg, elemDef, childPath+"[]", subs)
						} else {
							recordAdditionalPath(elemDef.Name, childPath+"[]")
							recordChildPaths(reg, elemDef, childPath+"[]")
						}
					}
				}
			}
		}
	}
}

func recordAdditionalPath(typeName, path string) {
	if sub, ok := subsByType[typeName]; ok {
		sub.AlsoPaths = append(sub.AlsoPaths, path)
	}
}

// recordChildPaths recursively records additional paths for all children of an
// already-documented struct. This ensures that when the same struct type appears
// under multiple parents (e.g., OAuthServer under both apigw and verifier),
// child types (e.g., Client under Clients) also get their additional paths recorded.
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
			if childDef := reg.Lookup(typeName); childDef != nil {
				recordAdditionalPath(childDef.Name, childPath)
				recordChildPaths(reg, childDef, childPath)
				recorded = true
			}
		}

		// Named map type alias
		if !recorded && typeName != "" {
			if valDef := reg.LookupMapValueType(typeName); valDef != nil {
				recordAdditionalPath(valDef.Name, childPath+".<key>")
				recordChildPaths(reg, valDef, childPath+".<key>")
				recorded = true
			}
		}

		// Map with struct value
		if !recorded {
			if mt, ok := asMapType(f.TypeExpr); ok {
				valName := resolveTypeName(mt.Value)
				if valName != "" {
					if valDef := reg.Lookup(valName); valDef != nil {
						recordAdditionalPath(valDef.Name, childPath+".<key>")
						recordChildPaths(reg, valDef, childPath+".<key>")
					}
				}
			}
		}

		// Slice of structs
		if !recorded {
			if at, ok := f.TypeExpr.(*ast.ArrayType); ok {
				elemName := resolveTypeName(at.Elt)
				if elemName != "" {
					if elemDef := reg.Lookup(elemName); elemDef != nil {
						recordAdditionalPath(elemDef.Name, childPath+"[]")
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
	buf.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format("2006-01-02")))
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
	labels := map[string]string{
		"common":       "Common",
		"apigw":        "API Gateway (APIGW)",
		"issuer":       "Issuer",
		"verifier":     "Verifier",
		"registry":     "Registry",
		"mock_as":      "Mock AS",
		"ui":           "UI",
		"secrets_file": "Secrets File Reference",
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
	}
	for _, d := range dirs {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			continue
		}
		if err := reg.ParseDir(d); err != nil {
			log.Fatalf("error parsing %s: %v", d, err)
		}
	}

	sections := buildDocument(reg)
	markdown := renderDocument(sections)

	outPath := filepath.Join(root, *outFlag)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		log.Fatalf("creating output dir: %v", err)
	}
	if err := os.WriteFile(outPath, []byte(markdown), 0o644); err != nil {
		log.Fatalf("writing %s: %v", outPath, err)
	}
	fmt.Printf("Generated %s (%d bytes)\n", outPath, len(markdown))
}
