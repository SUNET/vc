package apiv1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/model"
)

// pidVCTM is a minimal type metadata document. Its exact bytes are what
// matters here: vct#integrity in every issued credential is a digest over
// them, so TypeMetadata must hand back these bytes and not a re-serialisation.
const pidVCTM = `{"vct":"urn:eudi:pid:arf-1.8:1","name":"PID","claims":[{"path":["given_name"]}]}`

// loadedMetadata builds a CredentialMetadata the way LoadCredentialSchema
// would for the given source, without reaching for a registry or the network.
func loadedMetadata(t *testing.T, source func(*model.CredentialMetadata), raw string) *model.CredentialMetadata {
	t.Helper()
	c := &model.CredentialMetadata{Format: "dc+sd-jwt"}
	source(c)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(raw))
	}))
	t.Cleanup(srv.Close)
	// Route every source through the URL loader: it is the one path that
	// exercises loadVCTM without a registry client, and what it stores in
	// VCTMRaw is the same for all of them.
	c.VCTMUrl = srv.URL
	require.NoError(t, c.LoadCredentialSchema(context.Background(), "pid_1_8", nil))
	source(c) // restore the source under test, now that the document is loaded
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
		name   string
		source func(*model.CredentialMetadata)
	}{
		{
			name:   "registry-resolved (vct)",
			source: func(c *model.CredentialMetadata) { c.VCTMFilePath = ""; c.VCT = "urn:eudi:pid:arf-1.8:1" },
		},
		{
			name:   "URL-resolved (vctm_url)",
			source: func(c *model.CredentialMetadata) { c.VCTMFilePath = "" },
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			meta := loadedMetadata(t, tt.source, pidVCTM)
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
