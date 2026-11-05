package legacyclaims

import (
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/goccy/go-yaml/ast"
)

// Shapes supplies the shapes of the credentials a configuration names, by
// credential scope.
type Shapes interface {
	// Presented returns the shape of the claims of a presented credential
	// of scope.
	Presented(scope string) (Shape, error)
	// Document returns the shape of the document of a credential of scope.
	Document(scope string) (Shape, error)
}

// lazy is a shape read on first use, so a configuration written in the
// current forms loads no schema for the upgrade.
type lazy struct {
	get   func() (Shape, error)
	shape Shape
	err   error
	done  bool
}

func newLazy(get func() (Shape, error)) *lazy { return &lazy{get: get} }

func (l *lazy) read() (Shape, error) {
	if !l.done {
		l.shape, l.err = l.get()
		l.done = true
	}
	return l.shape, l.err
}

func (l *lazy) dotted(name string) (claimpath.Pointer, error) {
	shape, err := l.read()
	if err != nil {
		return claimpath.Pointer{}, err
	}
	return shape.Dotted(name)
}

func (l *lazy) literal(name string) (claimpath.Pointer, error) {
	shape, err := l.read()
	if err != nil {
		return claimpath.Pointer{}, err
	}
	return shape.Literal(name)
}

// reader returns the literal reading of a claim name when literal is
// set, and the dotted reading otherwise.
func (l *lazy) reader(literal bool) reader {
	if literal {
		return l.literal
	}
	return l.dotted
}

func (l *lazy) topLevel(name string) (claimpath.Pointer, error) {
	shape, err := l.read()
	if err != nil {
		return claimpath.Pointer{}, err
	}
	return shape.TopLevel(name)
}

// UpgradeConfig rewrites the claim spellings of earlier releases in a
// service configuration: UpgradeShared, then UpgradeDataSources.
func UpgradeConfig(d *Document, shapes Shapes) error {
	if err := UpgradeShared(d); err != nil {
		return err
	}
	return UpgradeDataSources(d, shapes)
}

// UpgradeShared rewrites the claim spellings outside apigw.data_sources,
// which read no credential schema: the auth provider attribute mappings,
// the verifier presets and binding attributes, and the auxiliary_data
// paths.
func UpgradeShared(d *Document) error {
	if d.root == nil {
		return nil
	}
	for _, upgrade := range []func() error{d.upgradeAuthProviders, d.upgradePresets, d.upgradeBindingAttributes, d.upgradeAuxiliaryData} {
		if err := upgrade(); err != nil {
			return d.fail(err)
		}
	}
	return nil
}

// UpgradeDataSources rewrites the claim spellings of apigw.data_sources,
// each read in the shape of the credential that holds it.
func UpgradeDataSources(d *Document, shapes Shapes) error {
	if d.root == nil {
		return nil
	}
	return d.fail(d.upgradeDataSources(shapes))
}

// upgradeDataSources is UpgradeDataSources for a document with a root.
func (d *Document) upgradeDataSources(shapes Shapes) error {
	dataSources, err := descend(d.root, "apigw", "data_sources")
	if err != nil || isNull(dataSources) {
		return err
	}
	u := &configUpgrade{Document: d, shapes: shapes}
	for _, section := range []struct {
		key     string
		upgrade func(scope string, n ast.Node) error
	}{
		{"datastore", u.datastoreScope},
		{"assertion", u.assertionScope},
		{"external_api", u.externalAPIScope},
		{"presentation", u.presentationScope},
	} {
		if err := u.eachScope(dataSources, section.key, section.upgrade); err != nil {
			return err
		}
	}
	return nil
}

// configUpgrade upgrades the data sources of one configuration.
type configUpgrade struct {
	*Document
	shapes Shapes
}

func (u *configUpgrade) presented(scope string) *lazy {
	return newLazy(func() (Shape, error) { return u.shapes.Presented(scope) })
}

func (u *configUpgrade) document(scope string) *lazy {
	return newLazy(func() (Shape, error) { return u.shapes.Document(scope) })
}

// eachScope upgrades each scope of a data source.
func (u *configUpgrade) eachScope(dataSources ast.Node, source string, upgrade func(scope string, n ast.Node) error) error {
	scopes, err := descend(dataSources, source, "scopes")
	if err != nil {
		return err
	}
	list, err := entries(scopes)
	if err != nil {
		return err
	}
	for _, entry := range list {
		scope, err := keyOf(entry)
		if err != nil {
			return err
		}
		if err := upgrade(scope, entry.Value); err != nil {
			return err
		}
	}
	return nil
}

// upgradeAuthProviders reads the claim each auth provider attribute
// writes, split on dots into the JSON object of the mapped claims.
func (d *Document) upgradeAuthProviders() error {
	for _, provider := range []string{"saml", "oidc"} {
		mapping, err := descend(d.root, "apigw", "auth_providers", provider, "attribute_mapping")
		if err != nil {
			return err
		}
		if err := d.attributeMapping(mapping, Nested().Dotted); err != nil {
			return err
		}
	}
	return nil
}

// attributeMapping reads the claim of each attribute of a mapping.
func (d *Document) attributeMapping(mapping ast.Node, read reader) error {
	attributes, err := entries(mapping)
	if err != nil {
		return err
	}
	for _, attribute := range attributes {
		claim, err := child(attribute.Value, "claim")
		if err != nil {
			return err
		}
		if claim == nil {
			continue
		}
		if _, _, err := d.pointer(claim.Value, read); err != nil {
			return err
		}
	}
	return nil
}

// datastoreScope upgrades the auth scopes and derivations of a datastore
// scope. The derivations read and write the scope's document.
func (u *configUpgrade) datastoreScope(scope string, n ast.Node) error {
	authScopes, err := descend(n, "auth_scopes")
	if err != nil {
		return err
	}
	list, err := entries(authScopes)
	if err != nil {
		return err
	}
	for _, entry := range list {
		authScope, err := keyOf(entry)
		if err != nil {
			return err
		}
		if err := u.authScope(entry.Value, u.presented(authScope), u.document(scope)); err != nil {
			return err
		}
	}
	document := u.document(scope)
	return u.derivationsOf(n, document, document, nil)
}

// assertionScope upgrades the defaults and derivations of an assertion
// scope.
func (u *configUpgrade) assertionScope(scope string, n ast.Node) error {
	document := u.document(scope)
	if err := u.defaults(n, document); err != nil {
		return err
	}
	return u.derivationsOf(n, document, document, nil)
}

// externalAPIScope upgrades the attribute mapping and derivations of an
// external_api scope. The mapping writes the scope's document.
func (u *configUpgrade) externalAPIScope(scope string, n ast.Node) error {
	document := u.document(scope)
	mapping, err := descend(n, "attribute_mapping")
	if err != nil {
		return err
	}
	if err := u.attributeMapping(mapping, document.dotted); err != nil {
		return err
	}
	return u.derivationsOf(n, document, document, nil)
}

// presentationScope upgrades the defaults of a presentation scope, and the
// required claims and derivations of each credential it accepts.
func (u *configUpgrade) presentationScope(scope string, n ast.Node) error {
	document := u.document(scope)
	if err := u.defaults(n, document); err != nil {
		return err
	}
	from, err := descend(n, "from")
	if err != nil {
		return err
	}
	accepted, err := entries(from)
	if err != nil {
		return err
	}
	for _, entry := range accepted {
		presented, err := keyOf(entry)
		if err != nil {
			return err
		}
		if err := u.presentedCredential(entry.Value, u.presented(presented), document); err != nil {
			return err
		}
	}
	return nil
}

// defaults rewrites a defaults map {claim: value} as a list of claims of
// the document.
func (u *configUpgrade) defaults(n ast.Node, document *lazy) error {
	defaults, err := descend(n, "defaults")
	if err != nil || !isMapping(defaults) {
		return err
	}
	return u.convertMap(defaults, func(key string, _ ast.Node) (listEntry, error) {
		path, err := document.dotted(key)
		return listEntry{keyField: "path", key: path, valueField: "value"}, err
	})
}

// derivationsOf upgrades the derivations of a scope or of an accepted
// credential, after the copies the upgrade prepends to them.
func (u *configUpgrade) derivationsOf(n ast.Node, source, issued *lazy, prepended []claimpath.Pointer) error {
	derivations, err := descend(n, "derivations")
	if err != nil {
		return err
	}
	return u.derivations(derivations, source, issued, prepended)
}

// isMapping reports whether a node is a mapping: main's map form of a
// list.
func isMapping(n ast.Node) bool {
	n, err := unwrap(n)
	if err != nil {
		// An alias: the strict decoder reads it and refuses a map.
		return false
	}
	switch n.(type) {
	case *ast.MappingNode, *ast.MappingValueNode:
		return true
	}
	return false
}

// ClearDataSources empties apigw.data_sources, for a service that reads
// no data source.
func ClearDataSources(d *Document) error {
	if d.root == nil {
		return nil
	}
	return d.fail(d.clearDataSources())
}

// clearDataSources is ClearDataSources for a document with a root.
func (d *Document) clearDataSources() error {
	apigw, err := descend(d.root, "apigw")
	if err != nil {
		return err
	}
	entry, err := child(apigw, "data_sources")
	if err != nil || entry == nil || isNull(entry.Value) {
		return err
	}
	value, err := unwrap(entry.Value)
	if err != nil {
		return err
	}
	if start, end, err := d.span(value); err == nil {
		d.replace(start, end, "{}")
		return nil
	}
	colon, err := d.offset(entry.Start.Position)
	if err != nil {
		return err
	}
	d.replace(colon+1, d.lineEnd(lastLine(value)), " {}")
	return nil
}

// upgradePresets upgrades the claim paths of the verifier presets.
func (d *Document) upgradePresets() error {
	presets, err := descend(d.root, "verifier", "presets")
	if err != nil {
		return err
	}
	list, err := entries(presets)
	if err != nil {
		return err
	}
	for _, preset := range list {
		credentials, err := descend(preset.Value, "credentials")
		if err != nil {
			return err
		}
		scopes, err := entries(credentials)
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			if err := d.presetScope(scope.Value); err != nil {
				return err
			}
		}
	}
	return nil
}

// presetScope upgrades the claim paths of one preset credential: those of
// its claims and exclude_claims, where main read the string "null" as
// every element of an array, and those of its validations.
func (d *Document) presetScope(n ast.Node) error {
	for _, key := range []string{"claims", "exclude_claims", "validations"} {
		entries, err := descend(n, key)
		if err != nil {
			return err
		}
		list, err := items(entries)
		if err != nil {
			return err
		}
		for _, entry := range list {
			path, err := descend(entry, "path")
			if err != nil {
				return err
			}
			if err := d.stringPath(path, key != "validations"); err != nil {
				return err
			}
		}
	}
	return nil
}

// upgradeBindingAttributes upgrades the paths of each binding attribute of
// the verifier's combined presentation. Main split each on dots in the
// verified claims of every credential.
func (d *Document) upgradeBindingAttributes() error {
	attributes, err := descend(d.root, "verifier", "combined_presentation", "binding_attributes")
	if err != nil {
		return err
	}
	list, err := items(attributes)
	if err != nil {
		return err
	}
	for _, attribute := range list {
		paths, err := descend(attribute, "paths")
		if err != nil {
			return err
		}
		claims, err := items(paths)
		if err != nil {
			return err
		}
		for _, claim := range claims {
			if _, _, err := d.pointer(claim, Nested().Dotted); err != nil {
				return err
			}
		}
	}
	return nil
}

// upgradeAuxiliaryData upgrades the path of each auxiliary_data entry of
// each credential.
func (d *Document) upgradeAuxiliaryData() error {
	metadata, err := descend(d.root, "common", "credential_metadata")
	if err != nil {
		return err
	}
	scopes, err := entries(metadata)
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		for _, direction := range []string{"to_wallet", "to_issuer"} {
			list, err := descend(scope.Value, "auxiliary_data", direction)
			if err != nil {
				return err
			}
			items, err := items(list)
			if err != nil {
				return err
			}
			for _, item := range items {
				path, err := descend(item, "path")
				if err != nil {
					return err
				}
				if err := d.stringPath(path, false); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// stringPath upgrades a claim path main read as a list of strings. A
// scalar other than an integer that YAML reads as no string, such as true
// or 1.5, is the key of its text, so it becomes a quoted string. With
// nullString, the string "null" is every element of an array, so it
// becomes YAML null. A path that is no list stays as written: main read
// none, and the strict decoder refuses it.
func (d *Document) stringPath(path ast.Node, nullString bool) error {
	path, err := unwrap(path)
	if err != nil {
		return err
	}
	sequence, isList := path.(*ast.SequenceNode)
	if !isList {
		return nil
	}
	for _, component := range sequence.Values {
		component, err := unwrap(component)
		if err != nil {
			return err
		}
		text, ok := plainKey(component)
		if s, isString := component.(*ast.StringNode); nullString && isString && s.Value == "null" {
			text, ok = "null", true
		}
		if !ok {
			continue
		}
		start, end, err := d.span(component)
		if err != nil {
			return err
		}
		d.replace(start, end, text)
		if err := d.record(component, strings.TrimSpace(string(d.src[start:end])), text); err != nil {
			return err
		}
	}
	return nil
}
