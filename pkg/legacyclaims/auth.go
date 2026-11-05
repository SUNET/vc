package legacyclaims

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/goccy/go-yaml/ast"
)

// identityAttributes are the identity-mapping attributes an auth claim is
// matched as.
var identityAttributes = map[string]bool{
	"given_name": true, "family_name": true, "birth_date": true, "authentic_source_person_id": true,
}

// bareAlias reports whether a dotted name of a presented mdoc is a bare
// element identifier: main stored its claim under that identifier.
func (s Shape) bareAlias(name string) bool {
	return s.kind == qualifiedReading && !strings.Contains(name, ".")
}

// renamed is an auth claim main matched under its bare mdoc element
// identifier, which the upgrade names in identity_attributes.
type renamed struct {
	path claimpath.Pointer
	// attribute is the element identifier.
	attribute string
	// record is the index of the auth claim's rewrite record.
	record int
}

// authScope upgrades the claims of an auth scope entry: its auth claims,
// identity attributes and document claims read the presented credential,
// and a document claim's target is a top-level claim of the issued
// document.
//
// main matched an auth claim under its identity_attributes entry, or under
// the claim as spelled. An mdoc auth claim spelled as a bare element
// identifier, such as given_name, gains the identity_attributes entry that
// keeps it matched under that identifier.
func (u *configUpgrade) authScope(n ast.Node, presented, document *lazy) error {
	bare, err := u.authClaims(n, presented)
	if err != nil {
		return err
	}
	existing, err := u.identityAttributes(n, presented)
	if err != nil {
		return err
	}
	if err := u.documentClaims(n, presented, document); err != nil {
		return err
	}
	missing := slices.DeleteFunc(bare, func(r renamed) bool {
		return slices.ContainsFunc(existing, r.path.Equal)
	})
	return u.addRenames(n, missing)
}

// authClaims reads the auth claims, and returns those main matched under
// a bare mdoc element identifier.
func (u *configUpgrade) authClaims(n ast.Node, presented *lazy) ([]renamed, error) {
	claims, err := descend(n, "auth_claims")
	if err != nil {
		return nil, err
	}
	list, err := items(claims)
	if err != nil {
		return nil, err
	}
	var bare []renamed
	for _, item := range list {
		item, err := unwrap(item)
		if err != nil {
			return nil, err
		}
		name, _ := dottedName(item)
		path, rewritten, err := u.pointer(item, presented.dotted)
		if err != nil || !rewritten || !identityAttributes[name] {
			if err != nil {
				return nil, err
			}
			continue
		}
		shape, err := presented.read()
		if err != nil {
			return nil, err
		}
		if shape.bareAlias(name) {
			bare = append(bare, renamed{path: path, attribute: name, record: len(u.rewrites) - 1})
		}
	}
	return bare, nil
}

// identityAttributes rewrites the map {auth claim: attribute} as a list,
// and returns the auth claims it names.
func (u *configUpgrade) identityAttributes(n ast.Node, presented *lazy) ([]claimpath.Pointer, error) {
	renames, err := descend(n, "identity_attributes")
	if err != nil {
		return nil, err
	}
	var paths []claimpath.Pointer
	if isMapping(renames) {
		err := u.convertMap(renames, func(key string, _ ast.Node) (listEntry, error) {
			path, err := presented.dotted(key)
			paths = append(paths, path)
			return listEntry{keyField: "path", key: path, valueField: "attribute"}, err
		})
		return paths, err
	}
	list, err := items(renames)
	if err != nil {
		return nil, err
	}
	for _, item := range list {
		path, err := descend(item, "path")
		if err != nil {
			return nil, err
		}
		if p, err := pointerOf(path); err == nil {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// documentClaims rewrites the map {presented claim: issued claim} as a
// list of copies.
func (u *configUpgrade) documentClaims(n ast.Node, presented, document *lazy) error {
	copies, err := descend(n, "document_claims")
	if err != nil || !isMapping(copies) {
		return err
	}
	return u.convertMap(copies, func(key string, value ast.Node) (listEntry, error) {
		from, err := presented.dotted(key)
		if err != nil {
			return listEntry{}, err
		}
		item := listEntry{keyField: "from", key: from, valueField: "to"}
		value, err = unwrap(value)
		if err != nil {
			return listEntry{}, err
		}
		if name, ok := dottedName(value); ok {
			to, err := document.topLevel(name)
			if err != nil {
				return listEntry{}, fmt.Errorf("to: %w", err)
			}
			item.value = &to
		}
		return item, nil
	})
}

// addRenames adds an identity_attributes entry for each auth claim main
// matched under its bare mdoc element identifier.
func (u *configUpgrade) addRenames(n ast.Node, missing []renamed) error {
	if len(missing) == 0 {
		return nil
	}
	texts := make([]string, len(missing))
	for i, r := range missing {
		path, err := pointerText(r.path)
		if err != nil {
			return err
		}
		texts[i] = "{path: " + path + ", attribute: " + r.attribute + "}"
		u.rewrites[r.record].New += "; identity_attributes gains " + texts[i]
	}
	return u.extendList(n, "identity_attributes", "auth_claims", texts)
}

// extendList appends flow items to the list under key of mapping n. An
// absent key is added after the entry after.
func (u *configUpgrade) extendList(n ast.Node, key, after string, texts []string) error {
	entry, err := child(n, key)
	if err != nil {
		return err
	}
	if entry != nil && !isNull(entry.Value) {
		return u.appendItems(entry.Value, texts)
	}
	list := "[" + strings.Join(texts, ", ") + "]"
	if entry != nil {
		return u.setNull(entry, list)
	}
	return u.addAfter(n, after, key, list)
}

// addAfter adds the entry key: value to mapping n after its entry after.
func (u *configUpgrade) addAfter(n ast.Node, after, key, value string) error {
	n, err := unwrap(n)
	if err != nil {
		return err
	}
	mapping, ok := n.(*ast.MappingNode)
	if !ok {
		return fmt.Errorf("%s is no mapping", n.GetPath())
	}
	entry, err := child(mapping, after)
	if err != nil {
		return err
	}
	if entry == nil {
		entry = mapping.Values[len(mapping.Values)-1]
	}
	return u.addEntry(mapping, entry, key, value)
}

// setNull writes text as the value of an entry whose value is null.
func (d *Document) setNull(entry *ast.MappingValueNode, text string) error {
	if tk := entry.Value.GetToken(); tk != nil && strings.TrimSpace(tk.Origin) != "" {
		start, end, err := d.span(entry.Value)
		if err != nil {
			return err
		}
		d.replace(start, end, text)
		return nil
	}
	colon, err := d.offset(entry.Start.Position)
	if err != nil {
		return err
	}
	d.insert(colon+1, " "+text)
	return nil
}
