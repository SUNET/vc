package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/model"
	ts11client "github.com/sirosfoundation/go-ts11client"
)

// pidVCTM is a minimal type metadata document. Its exact bytes are what
// matters here: vct#integrity in every issued credential is a digest over
// them, so TypeMetadata must hand back these bytes and not a re-serialisation.
const pidVCTM = `{"vct":"urn:eudi:pid:arf-1.8:1","name":"PID","claims":[{"path":["given_name"]}]}`

// stubRegistry is a ts11client.Client double, so the registry-resolved case
// actually goes through loadVCTM's registry branch rather than the URL one.
type stubRegistry struct{ vctm map[string][]byte }

func (s *stubRegistry) ResolveVCT(_ context.Context, vct string) (*ts11client.Resolved, error) {
	data, ok := s.vctm[vct]
	if !ok {
		return nil, fmt.Errorf("%w: vct=%s", ts11client.ErrNotFound, vct)
	}
	return &ts11client.Resolved{Data: data, Source: "stub"}, nil
}

func (s *stubRegistry) ResolveDoctype(_ context.Context, doctype string) (*ts11client.Resolved, error) {
	return nil, fmt.Errorf("%w: doctype=%s", ts11client.ErrNotFound, doctype)
}

// loadedFromRegistry loads a scope the way a vct-configured deployment does.
func loadedFromRegistry(t *testing.T, vct, raw string) *model.CredentialMetadata {
	t.Helper()
	c := &model.CredentialMetadata{Format: "dc+sd-jwt", VCT: vct}
	registry := &stubRegistry{vctm: map[string][]byte{vct: []byte(raw)}}
	require.NoError(t, c.LoadCredentialSchema(context.Background(), "pid_1_8", registry))
	return c
}

// loadedFromURL loads a scope the way a vctm_url-configured deployment does.
func loadedFromURL(t *testing.T, raw string) *model.CredentialMetadata {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(raw))
	}))
	t.Cleanup(srv.Close)

	c := &model.CredentialMetadata{Format: "dc+sd-jwt", VCTMUrl: srv.URL}
	require.NoError(t, c.LoadCredentialSchema(context.Background(), "pid_1_8", nil))
	return c
}

func typeMetadataClient(scope string, c *model.CredentialMetadata) *Client {
	return &Client{cfg: &model.Cfg{
		Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{scope: c}},
	}}
}

// TestTypeMetadata_ServesExactBytes is the contract this endpoint exists for:
// whatever the source, the served document must be byte-identical to the one
// the issuer computed vct#integrity over, or a wallet cannot verify the pin.
func TestTypeMetadata_ServesExactBytes(t *testing.T) {
	tts := []struct {
		name string
		load func(*testing.T) *model.CredentialMetadata
	}{
		{
			name: "registry-resolved (vct)",
			load: func(t *testing.T) *model.CredentialMetadata {
				return loadedFromRegistry(t, "urn:eudi:pid:arf-1.8:1", pidVCTM)
			},
		},
		{
			name: "URL-resolved (vctm_url)",
			load: func(t *testing.T) *model.CredentialMetadata { return loadedFromURL(t, pidVCTM) },
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			meta := tt.load(t)
			require.False(t, meta.IsLocalVCTM(), "the point of this case is a non-local source")

			client := typeMetadataClient("pid_1_8", meta)
			reply, err := client.TypeMetadata(context.Background(), &TypeMetadataRequest{Scope: "pid_1_8"})
			require.NoError(t, err, "a resolved document must be served, not refused")

			assert.Equal(t, meta.GetVCTMRaw(), []byte(reply), "served bytes must be exactly VCTMRaw")
			assert.JSONEq(t, pidVCTM, string(reply))
		})
	}
}

// TestTypeMetadata_UnknownScope keeps the error path honest.
func TestTypeMetadata_UnknownScope(t *testing.T) {
	client := typeMetadataClient("pid_1_8", &model.CredentialMetadata{})
	_, err := client.TypeMetadata(context.Background(), &TypeMetadataRequest{Scope: "nope"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scope")
}

// TestTypeMetadata_NotLoaded covers a scope that exists but whose document
// never loaded: there is nothing to serve, and saying so beats serving null.
func TestTypeMetadata_NotLoaded(t *testing.T) {
	client := typeMetadataClient("pid_1_8", &model.CredentialMetadata{Format: "dc+sd-jwt", VCT: "urn:eudi:pid:arf-1.8:1"})
	_, err := client.TypeMetadata(context.Background(), &TypeMetadataRequest{Scope: "pid_1_8"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VCTM not loaded")
}

// TestTypeMetadata_LocalMDDLStillWins keeps the mdoc branch ahead of the
// VCTM one, as it was before externally-resolved documents became servable.
func TestTypeMetadata_LocalMDDLStillWins(t *testing.T) {
	const mddl = `{"format":"mso_mdoc","doctype":"org.iso.18013.5.1.mDL","claims":{"org.iso.18013.5.1":{"family_name":{"mandatory":true,"value_type":"tstr"}}}}`
	path := t.TempDir() + "/mdl.mdoc.json"
	require.NoError(t, writeFile(path, mddl))

	c := &model.CredentialMetadata{Format: "mso_mdoc", MDDLFilePath: path}
	require.NoError(t, c.LoadCredentialSchema(context.Background(), "mdl", nil))
	require.True(t, c.IsLocalMDDL())

	client := typeMetadataClient("mdl", c)
	reply, err := client.TypeMetadata(context.Background(), &TypeMetadataRequest{Scope: "mdl"})
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(reply, &got))
	assert.Equal(t, "org.iso.18013.5.1.mDL", got["doctype"])
	assert.Equal(t, c.GetMDDLRaw(), []byte(reply))
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
