package legacyclaims

import (
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/goccy/go-yaml/ast"
)

// presentedCredential upgrades the required claims and derivations of a
// credential a presentation scope accepts.
//
// main kept a required claim under its spelling, and the issued document
// starts from the required claims. An mdoc claim spelled as a bare element
// identifier, such as birth_date, so reached the document under that
// identifier. The loader carries the identifier beside the pointer, and
// the verified claims hold the claim under it, as main's did. A copy at
// the start of the derivations puts the claim there in the issued
// document when the verified claims hold it under its namespace, as the
// converted file stores it. A claim an opening takes as its secret gets
// no copy: the configuration keeps that claim out of the credential.
func (u *configUpgrade) presentedCredential(n ast.Node, presented, document *lazy) error {
	derivations, err := descend(n, "derivations")
	if err != nil {
		return err
	}
	secrets, err := claimOpenings(derivations, presented)
	if err != nil {
		return err
	}
	required, err := descend(n, "required_claims")
	if err != nil {
		return err
	}
	var copies []string
	var outputs []claimpath.Pointer
	if isMapping(required) {
		err := u.convertMap(required, func(key string, _ ast.Node) (listEntry, error) {
			path, err := presented.dotted(key)
			if err != nil {
				return listEntry{}, err
			}
			entry := listEntry{keyField: "path", key: path, valueField: "values", omitEmpty: true}
			shape, err := presented.read()
			if err != nil || !shape.bareAlias(key) {
				return entry, err
			}
			if !u.convert {
				entry.dotted = key
			}
			if slices.ContainsFunc(secrets, path.Equal) {
				return entry, nil
			}
			output, err := document.topLevel(key)
			if err != nil {
				return listEntry{}, err
			}
			text, err := copyText(path, output)
			if err != nil {
				return listEntry{}, err
			}
			copies = append(copies, text)
			outputs = append(outputs, output)
			entry.note = "; derivations start with " + text
			return entry, nil
		})
		if err != nil {
			return err
		}
	}
	if err := u.prependDerivations(n, derivations, copies); err != nil {
		return err
	}
	return u.derivations(derivations, presented, document, outputs)
}

// copyText renders a copy derivation as a flow mapping.
func copyText(input, output claimpath.Pointer) (string, error) {
	in, err := pointerText(input)
	if err != nil {
		return "", err
	}
	out, err := pointerText(output)
	if err != nil {
		return "", err
	}
	return "{copy: {input: " + in + ", output: " + out + "}}", nil
}

// prependDerivations puts derivations before the list of n.
func (u *configUpgrade) prependDerivations(n, derivations ast.Node, texts []string) error {
	if len(texts) == 0 {
		return nil
	}
	if !isNull(derivations) {
		return u.prependItems(derivations, texts)
	}
	entry, err := child(n, "derivations")
	if err != nil {
		return err
	}
	list := "[" + strings.Join(texts, ", ") + "]"
	if entry != nil {
		return u.setNull(entry, list)
	}
	return u.addAfter(n, "required_claims", "derivations", list)
}

// claimOpenings returns the claims the claim openings of a derivation list
// take as their secret.
func claimOpenings(derivations ast.Node, source *lazy) ([]claimpath.Pointer, error) {
	nodes, err := items(derivations)
	if err != nil {
		return nil, err
	}
	var secrets []claimpath.Pointer
	for _, node := range nodes {
		input, err := descend(node, "hash_commitment", "opening", "claim", "input")
		if err != nil {
			return nil, err
		}
		input, err = unwrap(input)
		if err != nil || isNull(input) {
			if err != nil {
				return nil, err
			}
			continue
		}
		if name, ok := dottedName(input); ok {
			p, err := source.dotted(name)
			if err != nil {
				return nil, err
			}
			secrets = append(secrets, p)
			continue
		}
		p, err := pointerOf(input)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, p)
	}
	return secrets, nil
}
