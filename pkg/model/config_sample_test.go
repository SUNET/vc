package model

import (
	"os"
	"testing"

	"gopkg.in/yaml.v2"
)

// TestSampleConfigPresetsMatchSchema guards the repository's own config.yaml
// against the preset schema drifting away from it.
//
// The presets shape is a breaking change, and a preset left in the old form
// (scopes directly under the label, with no credentials key) decodes without
// error into a PresetDefinition with no credentials - so it survives config
// load and shows up as a button that selects nothing. Nothing about the YAML
// looks wrong, which is why this is a test rather than a review item.
func TestSampleConfigPresetsMatchSchema(t *testing.T) {
	b, err := os.ReadFile("../../config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	// Lenient, matching how configuration.New loads it: the sample config
	// carries keys this package does not model, and pinning those is not this
	// test's job.
	var cfg Cfg
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("config.yaml does not decode: %v", err)
	}

	if cfg.Verifier == nil {
		t.Fatal("config.yaml parsed no verifier block")
	}
	if len(cfg.Verifier.Presets) == 0 {
		t.Fatal("config.yaml parsed no verifier presets")
	}
	for label, preset := range cfg.Verifier.Presets {
		if len(preset.Credentials) == 0 {
			t.Errorf("preset %q has no credentials: still in the pre-PresetDefinition schema?", label)
		}
	}
}
