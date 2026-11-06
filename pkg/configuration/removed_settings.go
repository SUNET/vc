package configuration

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v2"
)

// anyKey matches every key of a mapping in a removedSetting path.
const anyKey = "*"

// removedSetting is the YAML path of a setting a release removed, with
// anyKey for a segment the operator names.
type removedSetting []string

// removedSeedConfigSettings are the seed-commitment settings of the main
// configuration. A hash_commitment derivation replaces them.
var removedSeedConfigSettings = []removedSetting{
	{"apigw", "seeds"},
	{"common", "credential_metadata", anyKey, "commitments"},
}

// removedSeedSecretsSettings are the seed secrets of the secrets file.
var removedSeedSecretsSettings = []removedSetting{
	{"apigw", "seeds"},
}

// refuseRemovedSeedSettings returns one error per removed seed-commitment
// setting that data holds, naming its YAML path. A null value counts as
// present.
func refuseRemovedSeedSettings(data []byte, settings []removedSetting) error {
	var doc map[any]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	var found []string
	for _, setting := range settings {
		found = append(found, removedSettingPaths(doc, setting, nil)...)
	}
	slices.Sort(found)
	errs := make([]error, 0, len(found))
	for _, path := range found {
		errs = append(errs, fmt.Errorf("%s is removed: configure a hash_commitment derivation instead (docs/issuer/AUXILIARY_DATA.md)", path))
	}
	return errors.Join(errs...)
}

// removedSettingPaths returns the dotted path of each node under node that
// rest matches, prefixed with at.
func removedSettingPaths(node any, rest removedSetting, at []string) []string {
	if len(rest) == 0 {
		return []string{strings.Join(at, ".")}
	}
	mapping, ok := node.(map[any]any)
	if !ok {
		return nil
	}
	if rest[0] != anyKey {
		child, present := mapping[rest[0]]
		if !present {
			return nil
		}
		return removedSettingPaths(child, rest[1:], append(slices.Clone(at), rest[0]))
	}
	var paths []string
	for key, child := range mapping {
		paths = append(paths, removedSettingPaths(child, rest[1:], append(slices.Clone(at), fmt.Sprint(key)))...)
	}
	return paths
}
