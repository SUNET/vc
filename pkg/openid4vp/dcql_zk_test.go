package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

const mockZKCredentialQuery = `{
  "id": "cred1",
  "format": "mso_mdoc_zk",
  "meta": {
    "doctype_value": "org.iso.18013.5.1.mDL",
    "zk_system_type": [
      {
        "id": "longfellow-libzk-v1_8_1_4259_2945",
        "system": "longfellow-libzk-v1",
        "num_attributes": 1,
        "circuit_hash": "4259_2945",
        "block_enc_hash": 4259,
        "block_enc_sig": 2945
      }
    ],
    "ppid_context": "https://verifier.example"
  }
}`

func TestZKSystemTypeSpec_UnmarshalJSON(t *testing.T) {
	var cq CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(mockZKCredentialQuery), &cq))

	assert.Equal(t, FormatMsoMdocZk, cq.Format)
	assert.Equal(t, "org.iso.18013.5.1.mDL", cq.Meta.DoctypeValue)
	assert.Equal(t, "https://verifier.example", cq.Meta.PPIDContext)

	require.Len(t, cq.Meta.ZKSystemType, 1)
	spec := cq.Meta.ZKSystemType[0]
	assert.Equal(t, "longfellow-libzk-v1_8_1_4259_2945", spec.ID)
	assert.Equal(t, "longfellow-libzk-v1", spec.System)
	assert.Equal(t, "1", spec.GetParam("num_attributes"))
	assert.Equal(t, "4259_2945", spec.GetParam("circuit_hash"))
	assert.Equal(t, "4259", spec.GetParam("block_enc_hash"))
	assert.Equal(t, "2945", spec.GetParam("block_enc_sig"))
}

func TestZKSystemTypeSpec_MarshalJSON_RoundTrip(t *testing.T) {
	original := ZKSystemTypeSpec{
		ID:     "longfellow-libzk-v1_8_1_4259_2945",
		System: "longfellow-libzk-v1",
		Params: map[string]string{"num_attributes": "1", "circuit_hash": "abc"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var roundTripped ZKSystemTypeSpec
	require.NoError(t, json.Unmarshal(data, &roundTripped))

	assert.Equal(t, original.ID, roundTripped.ID)
	assert.Equal(t, original.System, roundTripped.System)
	assert.Equal(t, original.Params, roundTripped.Params)
}

func TestZKSystemTypeSpec_UnmarshalJSON_MissingID(t *testing.T) {
	var spec ZKSystemTypeSpec
	err := json.Unmarshal([]byte(`{"system": "longfellow-libzk-v1"}`), &spec)
	assert.Error(t, err)
}

func TestZKSystemTypeSpec_UnmarshalJSON_MissingSystem(t *testing.T) {
	var spec ZKSystemTypeSpec
	err := json.Unmarshal([]byte(`{"id": "x"}`), &spec)
	assert.Error(t, err)
}

// mockZKCredentialQueryYAML mirrors mockZKCredentialQuery but as YAML - the
// real shape pkg/configuration's YAML-loaded presentation request
// templates use (gopkg.in/yaml.v2, the same package this test uses).
const mockZKCredentialQueryYAML = `
id: cred1
format: mso_mdoc_zk
meta:
  doctype_value: org.iso.18013.5.1.mDL
  zk_system_type:
    - id: longfellow-libzk-v1_8_1_4259_2945
      system: longfellow-libzk-v1
      num_attributes: "1"
      circuit_hash: "4259_2945"
      block_enc_hash: "4259"
      block_enc_sig: "2945"
  ppid_context: https://verifier.example
`

// TestZKSystemTypeSpec_UnmarshalYAML guards against a real gap: Params was
// tagged yaml:"-" with no custom UnmarshalYAML, so a YAML-authored
// presentation request template (loaded via gopkg.in/yaml.v2 by
// pkg/configuration.LoadPresentationRequests) could never actually set
// num_attributes/circuit_hash/etc for a zk_system_type entry, even though
// docs/CONFIGURATION.md documents ZK circuit configuration and MetaQuery's
// own ZKSystemType field carries a yaml tag implying it works. This test
// exercises the real gopkg.in/yaml.v2 package (not a hand-rolled stand-in)
// against the same CredentialQuery type pkg/configuration actually
// YAML-decodes.
func TestZKSystemTypeSpec_UnmarshalYAML(t *testing.T) {
	var cq CredentialQuery
	require.NoError(t, yaml.Unmarshal([]byte(mockZKCredentialQueryYAML), &cq))

	assert.Equal(t, FormatMsoMdocZk, cq.Format)
	assert.Equal(t, "org.iso.18013.5.1.mDL", cq.Meta.DoctypeValue)
	assert.Equal(t, "https://verifier.example", cq.Meta.PPIDContext)

	require.Len(t, cq.Meta.ZKSystemType, 1)
	spec := cq.Meta.ZKSystemType[0]
	assert.Equal(t, "longfellow-libzk-v1_8_1_4259_2945", spec.ID)
	assert.Equal(t, "longfellow-libzk-v1", spec.System)
	assert.Equal(t, "1", spec.GetParam("num_attributes"))
	assert.Equal(t, "4259_2945", spec.GetParam("circuit_hash"))
	assert.Equal(t, "4259", spec.GetParam("block_enc_hash"))
	assert.Equal(t, "2945", spec.GetParam("block_enc_sig"))
}

// TestZKSystemTypeSpec_MarshalYAML_RoundTrip confirms YAML round-tripping
// (marshal then unmarshal via the real gopkg.in/yaml.v2 package) preserves
// Params, mirroring TestZKSystemTypeSpec_MarshalJSON_RoundTrip for YAML.
func TestZKSystemTypeSpec_MarshalYAML_RoundTrip(t *testing.T) {
	original := ZKSystemTypeSpec{
		ID:     "longfellow-libzk-v1_8_1_4259_2945",
		System: "longfellow-libzk-v1",
		Params: map[string]string{"num_attributes": "1", "circuit_hash": "abc"},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var roundTripped ZKSystemTypeSpec
	require.NoError(t, yaml.Unmarshal(data, &roundTripped))

	assert.Equal(t, original.ID, roundTripped.ID)
	assert.Equal(t, original.System, roundTripped.System)
	assert.Equal(t, original.Params, roundTripped.Params)
}

func TestZKSystemTypeSpec_UnmarshalYAML_MissingID(t *testing.T) {
	var spec ZKSystemTypeSpec
	err := yaml.Unmarshal([]byte("system: longfellow-libzk-v1\n"), &spec)
	assert.Error(t, err)
}

func TestZKSystemTypeSpec_UnmarshalYAML_MissingSystem(t *testing.T) {
	var spec ZKSystemTypeSpec
	err := yaml.Unmarshal([]byte("id: x\n"), &spec)
	assert.Error(t, err)
}

func TestIsMdocZkFormat(t *testing.T) {
	assert.True(t, IsMdocZkFormat(FormatMsoMdocZk))
	assert.False(t, IsMdocZkFormat(FormatMsoMdoc))
	assert.False(t, IsMdocZkFormat("dc+sd-jwt"))
}

func TestMatchZKSystemType(t *testing.T) {
	requested := []ZKSystemTypeSpec{
		{ID: "a", System: "longfellow-libzk-v1"},
		{ID: "b", System: "longfellow-libzk-v1"},
	}

	spec, ok := MatchZKSystemType(requested, "b")
	require.True(t, ok)
	assert.Equal(t, "b", spec.ID)

	_, ok = MatchZKSystemType(requested, "c")
	assert.False(t, ok)

	_, ok = MatchZKSystemType(nil, "a")
	assert.False(t, ok)
}

func TestCopyDCQL_PreservesZkFields(t *testing.T) {
	src := &DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "cred1",
				Format: FormatMsoMdocZk,
				Meta: MetaQuery{
					DoctypeValue: "org.iso.18013.5.1.mDL",
					PPIDContext:  "https://verifier.example",
					ZKSystemType: []ZKSystemTypeSpec{
						{ID: "a", System: "longfellow-libzk-v1", Params: map[string]string{"num_attributes": "1"}},
					},
				},
			},
		},
	}

	dst := copyDCQL(src)
	require.Len(t, dst.Credentials, 1)
	assert.Equal(t, "https://verifier.example", dst.Credentials[0].Meta.PPIDContext)
	assert.Equal(t, "org.iso.18013.5.1.mDL", dst.Credentials[0].Meta.DoctypeValue)
	require.Len(t, dst.Credentials[0].Meta.ZKSystemType, 1)
	assert.Equal(t, "a", dst.Credentials[0].Meta.ZKSystemType[0].ID)
	assert.Equal(t, "1", dst.Credentials[0].Meta.ZKSystemType[0].GetParam("num_attributes"))

	// Mutating the copy must not affect the source (deep copy, not shared slices/maps).
	dst.Credentials[0].Meta.ZKSystemType[0].Params["num_attributes"] = "99"
	assert.Equal(t, "1", src.Credentials[0].Meta.ZKSystemType[0].GetParam("num_attributes"))
}

func TestValidateCredentialQuery_MsoMdocZk_RequiresDoctypeAndZkSystemType(t *testing.T) {
	// Missing doctype_value.
	err := ValidateCredentialQuery(CredentialQuery{
		Format: FormatMsoMdocZk,
		Meta: MetaQuery{
			ZKSystemType: []ZKSystemTypeSpec{{ID: "a", System: "longfellow-libzk-v1"}},
		},
	})
	assert.Error(t, err)

	// Missing zk_system_type.
	err = ValidateCredentialQuery(CredentialQuery{
		Format: FormatMsoMdocZk,
		Meta: MetaQuery{
			DoctypeValue: "org.iso.18013.5.1.mDL",
		},
	})
	assert.Error(t, err)

	// Both present - valid.
	err = ValidateCredentialQuery(CredentialQuery{
		Format: FormatMsoMdocZk,
		Meta: MetaQuery{
			DoctypeValue: "org.iso.18013.5.1.mDL",
			ZKSystemType: []ZKSystemTypeSpec{{ID: "a", System: "longfellow-libzk-v1"}},
		},
	})
	assert.NoError(t, err)
}
