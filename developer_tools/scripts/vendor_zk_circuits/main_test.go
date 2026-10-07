package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc/zkcircuit"
)

// catalogServer serves a manifest, descriptors and artifacts the way the
// real service does, so run() below exercises the real client.
func catalogServer(t *testing.T, circuits []map[string]any, artifacts map[string][]byte) string {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/manifest.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"manifestVersion": 1, "circuits": circuits})
	})
	for _, c := range circuits {
		descriptor := c
		mux.HandleFunc("/v1/circuits/"+descriptor["id"].(string)+".json", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(descriptor)
		})
	}
	for urlPath, body := range artifacts {
		data := body
		mux.HandleFunc("/"+strings.TrimPrefix(urlPath, "/"), func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(data)
		})
	}

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL
}

func artifactFor(body []byte, urlPath string) (map[string]any, string) {
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	if urlPath == "" {
		urlPath = "v1/artifacts/sha256/" + hash
	}
	return map[string]any{
		"url": urlPath, "hash": "sha256:" + hash,
		"compression": "none", "size": len(body),
	}, urlPath
}

func TestVendorWritesAUsableMirror(t *testing.T) {
	body := []byte("verifier key bytes")
	artifact, urlPath := artifactFor(body, "")

	source := catalogServer(t,
		[]map[string]any{{
			"id": "vega-mc-p256-v1-verifier-key-r12", "system": "vega-mc", "systemVersion": "12",
			"status": "active", "published": true,
			"docTypes": []string{"org.iso.18013.5.1.mDL"},
			"params":   map[string]any{"role": "verifier", "saltBytes": "32"},
			"artifact": artifact,
		}},
		map[string][]byte{urlPath: body},
	)

	out := t.TempDir()
	if err := run(t.Context(), source, out, "", "", true, false); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	// The mirror is usable BY THE CLIENT, which is the only property worth
	// asserting: a layout that is merely plausible is not a mirror.
	mirror := zkcircuit.NewClient("file://" + filepath.ToSlash(out))
	manifest, err := mirror.FetchManifest(t.Context())
	if err != nil {
		t.Fatalf("the vendored mirror does not serve a manifest: %v", err)
	}
	salt, err := manifest.SaltBytes([]string{"vega-mc"}, "org.iso.18013.5.1.mDL")
	if err != nil || salt != 32 {
		t.Fatalf("SaltBytes = %d, %v; want 32, nil", salt, err)
	}

	descriptor, err := mirror.FetchCircuit(t.Context(), "vega-mc-p256-v1-verifier-key-r12")
	if err != nil {
		t.Fatalf("FetchCircuit() error = %v", err)
	}
	got, err := mirror.DownloadArtifact(t.Context(), descriptor)
	if err != nil {
		t.Fatalf("DownloadArtifact() error = %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("artifact = %q, want %q", got, body)
	}
}

func TestVendorMetadataOnlyWritesNoArtifacts(t *testing.T) {
	body := []byte("verifier key bytes")
	artifact, urlPath := artifactFor(body, "")

	source := catalogServer(t,
		[]map[string]any{{
			"id": "vega-mc-p256-v1-verifier-key-r12", "system": "vega-mc",
			"status": "active", "published": true, "artifact": artifact,
			"params": map[string]any{"role": "verifier"},
		}},
		map[string][]byte{urlPath: body},
	)

	out := t.TempDir()
	if err := run(t.Context(), source, out, "", "", true, true); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(out, "v1", "manifest.json")); err != nil {
		t.Fatalf("the manifest should still be written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "v1", "artifacts")); !os.IsNotExist(err) {
		t.Errorf("-metadata-only must not download the ~130MB artifacts (%v)", err)
	}
}

// The manifest is remote data and this tool turns all of it into local
// paths - one file per entry, named by the catalog's own id, plus one per
// artifact at the catalog's own relative path.
func TestVendorRefusesToWriteOutsideTheMirror(t *testing.T) {
	body := []byte("x")

	t.Run("a circuit id that is a path", func(t *testing.T) {
		artifact, urlPath := artifactFor(body, "")
		source := catalogServer(t,
			[]map[string]any{{
				"id": "../../../../tmp/owned", "system": "vega-mc",
				"status": "active", "published": true, "artifact": artifact,
				"params": map[string]any{"role": "verifier"},
			}},
			map[string][]byte{urlPath: body},
		)

		out := t.TempDir()
		err := run(t.Context(), source, out, "", "", true, true)
		if err == nil {
			t.Fatal("expected a refusal")
		}
		if !strings.Contains(err.Error(), "unusable circuit id") {
			t.Fatalf("error = %v, want the id refused", err)
		}
		assertNothingOutside(t, out)
	})

	t.Run("an artifact URL that escapes", func(t *testing.T) {
		artifact, _ := artifactFor(body, "../../../../tmp/owned.bin")
		source := catalogServer(t,
			[]map[string]any{{
				"id": "vega-verifier-r12", "system": "vega-mc",
				"status": "active", "published": true, "artifact": artifact,
				"params": map[string]any{"role": "verifier"},
			}},
			map[string][]byte{},
		)

		out := t.TempDir()
		err := run(t.Context(), source, out, "", "", true, false)
		if err == nil {
			t.Fatal("expected a refusal")
		}
		if !strings.Contains(err.Error(), "escapes the mirror root") {
			t.Fatalf("error = %v, want the artifact path refused", err)
		}
		assertNothingOutside(t, out)
	})
}

// assertNothingOutside checks the mirror holds only paths under itself -
// the property a traversal would break, and the one a "did it error?"
// assertion alone would not notice.
func assertNothingOutside(t *testing.T, out string) {
	t.Helper()
	root, err := filepath.Abs(out)
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(abs, root) {
			t.Errorf("%s is outside the mirror root %s", abs, root)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/tmp/owned"); err == nil {
		t.Error("/tmp/owned exists - a traversal wrote outside the mirror")
	}
	if _, err := os.Stat("/tmp/owned.bin"); err == nil {
		t.Error("/tmp/owned.bin exists - a traversal wrote outside the mirror")
	}
}

func TestSelectCircuits(t *testing.T) {
	manifest := &zkcircuit.Manifest{Circuits: []zkcircuit.CircuitDescriptor{
		{ID: "vega-active", System: "vega-mc", Status: "active", DocTypes: []string{"org.iso.18013.5.1.mDL"}},
		{ID: "vega-deprecated", System: "vega-mc", Status: "deprecated", DocTypes: []string{"org.iso.18013.5.1.mDL"}},
		{ID: "lf-active", System: "longfellow", Status: "active", DocTypes: []string{"org.iso.18013.5.1.mDL"}},
		{ID: "vega-pid", System: "vega-mc", Status: "active", DocTypes: []string{"eu.europa.ec.eudi.pid.1"}},
	}}

	got := selectCircuits(manifest, "vega-mc", "org.iso.18013.5.1.mDL", true)
	if len(got) != 1 || got[0].ID != "vega-active" {
		t.Fatalf("selectCircuits = %v, want [vega-active]", ids(got))
	}

	// -active-only=false keeps deprecated revisions, which is how a mirror
	// for a wallet population that has not rolled over yet is built.
	got = selectCircuits(manifest, "vega-mc", "org.iso.18013.5.1.mDL", false)
	if len(got) != 2 {
		t.Fatalf("selectCircuits = %v, want both mDL vega entries", ids(got))
	}
}

func ids(circuits []zkcircuit.CircuitDescriptor) []string {
	out := make([]string, len(circuits))
	for i, c := range circuits {
		out[i] = c.ID
	}
	return out
}

func TestArtifactPathRefusesWhatItCannotPlace(t *testing.T) {
	for name, artifact := range map[string]*zkcircuit.Artifact{
		"no hash and no url": {},
		"escaping url":       {URL: "../../x", Hash: "sha256:" + strings.Repeat("ab", 32)},
		"non-hex hash":       {Hash: "sha256:../../x"},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := artifactPath(artifact); err == nil {
				t.Fatalf("artifactPath() = %q; want a refusal", got)
			}
		})
	}
}
