package httpserver

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"
)

func TestBuildOpenIDRelyingPartyMetadata(t *testing.T) {
	t.Run("vp_formats omitted when nil", func(t *testing.T) {
		m := buildOpenIDRelyingPartyMetadata("https://verifier.example.com", "Example Verifier", "ES256", nil)

		if _, ok := m["vp_formats"]; ok {
			t.Errorf("expected \"vp_formats\" key to be absent, got %v", m["vp_formats"])
		}

		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("failed to marshal metadata: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("failed to unmarshal metadata: %v", err)
		}
		if _, ok := raw["vp_formats"]; ok {
			t.Errorf("expected serialized JSON to omit \"vp_formats\", got %s", data)
		}
	})

	t.Run("vp_formats present when configured", func(t *testing.T) {
		formats := &openid4vp.VPFormatsSupported{
			SDJWT: &openid4vp.SDJWTVCFormat{},
		}
		m := buildOpenIDRelyingPartyMetadata("https://verifier.example.com", "Example Verifier", "ES256", formats)

		if m["vp_formats"] != formats {
			t.Errorf("expected vp_formats = %v, got %v", formats, m["vp_formats"])
		}

		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("failed to marshal metadata: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("failed to unmarshal metadata: %v", err)
		}
		if _, ok := raw["vp_formats"]; !ok {
			t.Errorf("expected serialized JSON to include \"vp_formats\", got %s", data)
		}
	})

	t.Run("other fields always present", func(t *testing.T) {
		m := buildOpenIDRelyingPartyMetadata("client-id", "Client Name", "ES256", nil)

		if m["client_id"] != "client-id" {
			t.Errorf("client_id = %v, want client-id", m["client_id"])
		}
		if m["client_name"] != "Client Name" {
			t.Errorf("client_name = %v, want Client Name", m["client_name"])
		}
		if m["request_object_signing_alg"] != "ES256" {
			t.Errorf("request_object_signing_alg = %v, want ES256", m["request_object_signing_alg"])
		}
		responseTypes, ok := m["response_types"].([]string)
		if !ok || len(responseTypes) != 1 || responseTypes[0] != "vp_token" {
			t.Errorf("response_types = %v, want [vp_token]", m["response_types"])
		}
	})
}
