package configuration

import (
	"errors"
	"fmt"
	"slices"

	"gopkg.in/yaml.v2"
)

// removedSeedProbe decodes a file with the parent shapes of its typed
// configuration, so repeated sections, merges and unrelated subtrees decode as
// the loader decodes them.
type removedSeedProbe interface {
	// removedPaths returns the YAML path of each removed setting decoded.
	removedPaths() []string
}

// apigwSeedsProbe holds apigw.seeds, in both the configuration and the secrets
// file.
type apigwSeedsProbe struct {
	Seeds any `yaml:"seeds"`
}

func (p *apigwSeedsProbe) removedPaths() []string {
	if p == nil || p.Seeds == nil {
		return nil
	}
	return []string{"apigw.seeds"}
}

// seedConfigProbe holds the removed settings of the main configuration.
type seedConfigProbe struct {
	APIGW  *apigwSeedsProbe `yaml:"apigw"`
	Common *struct {
		CredentialMetadata map[string]*struct {
			Commitments any `yaml:"commitments"`
		} `yaml:"credential_metadata"`
	} `yaml:"common"`
}

func (p *seedConfigProbe) removedPaths() []string {
	found := p.APIGW.removedPaths()
	if p.Common == nil {
		return found
	}
	for scope, metadata := range p.Common.CredentialMetadata {
		if metadata != nil && metadata.Commitments != nil {
			found = append(found, "common.credential_metadata."+scope+".commitments")
		}
	}
	return found
}

// seedSecretsProbe holds the removed settings of the secrets file.
type seedSecretsProbe struct {
	APIGW *apigwSeedsProbe `yaml:"apigw"`
}

func (p *seedSecretsProbe) removedPaths() []string {
	return p.APIGW.removedPaths()
}

// refuseRemovedSeedSettings decodes data into probe and returns one error per
// removed seed-commitment setting found, naming its YAML path. A null value
// counts as absent: yaml.v2 decodes it to the zero value, and a later null
// clears an earlier value.
func refuseRemovedSeedSettings(data []byte, probe removedSeedProbe) error {
	if err := yaml.Unmarshal(data, probe); err != nil {
		return err
	}
	found := probe.removedPaths()
	slices.Sort(found)
	errs := make([]error, 0, len(found))
	for _, path := range found {
		errs = append(errs, fmt.Errorf("%s is removed: configure a hash_commitment derivation instead (docs/issuer/AUXILIARY_DATA.md)", path))
	}
	return errors.Join(errs...)
}
