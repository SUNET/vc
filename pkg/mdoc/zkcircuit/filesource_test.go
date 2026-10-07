package zkcircuit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeVendoredMirror lays out a directory the way
// developer_tools/scripts/vendor_zk_circuits does, and returns the file://
// URL a Sources entry would carry.
func writeVendoredMirror(t *testing.T, artifact []byte) string {
	t.Helper()
	dir := t.TempDir()

	sum := sha256.Sum256(artifact)
	hash := hex.EncodeToString(sum[:])
	artifactPath := "v1/artifacts/sha256/" + hash

	descriptor := `{
		"id": "vega-mc-p256-v1-prover-key-r12",
		"system": "vega-mc",
		"systemVersion": "12",
		"status": "active",
		"published": true,
		"docTypes": ["org.iso.18013.5.1.mDL"],
		"params": {"curve": "P-256", "saltBytes": "32"},
		"artifact": {"url": "` + artifactPath + `", "hash": "sha256:` + hash + `", "compression": "none", "size": ` +
		itoa(len(artifact)) + `}
	}`

	write(t, filepath.Join(dir, "v1", "manifest.json"), []byte(`{"manifestVersion":1,"circuits":[`+descriptor+`]}`))
	write(t, filepath.Join(dir, "v1", "circuits", "vega-mc-p256-v1-prover-key-r12.json"), []byte(descriptor))
	write(t, filepath.Join(dir, filepath.FromSlash(artifactPath)), artifact)

	return "file://" + filepath.ToSlash(dir)
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A vendored mirror is the same catalog reached a different way, so it
// goes through the same client with no second code path: manifest,
// descriptor and hash-verified artifact all come off disk.
func TestVendoredFileMirrorServesTheWholeCatalogAPI(t *testing.T) {
	artifact := []byte("not really a circuit, but hashed like one")
	source := writeVendoredMirror(t, artifact)
	c := NewClient(source)

	manifest, err := c.FetchManifest(t.Context())
	if err != nil {
		t.Fatalf("FetchManifest() error = %v", err)
	}
	salt, err := manifest.SaltBytes([]string{"vega-mc"}, "org.iso.18013.5.1.mDL")
	if err != nil || salt != 32 {
		t.Fatalf("SaltBytes = %d, %v; want 32, nil", salt, err)
	}

	descriptor, err := c.FetchCircuit(t.Context(), "vega-mc-p256-v1-prover-key-r12")
	if err != nil {
		t.Fatalf("FetchCircuit() error = %v", err)
	}

	got, err := c.DownloadArtifact(t.Context(), descriptor)
	if err != nil {
		t.Fatalf("DownloadArtifact() error = %v", err)
	}
	if string(got) != string(artifact) {
		t.Errorf("artifact = %q, want %q", got, artifact)
	}
}

// Vendoring pins the bytes; it does not relax verification. A mirror
// edited underneath fails exactly the way a tampered download does.
func TestVendoredArtifactStillHasToMatchItsHash(t *testing.T) {
	source := writeVendoredMirror(t, []byte("original bytes"))
	dir := strings.TrimPrefix(source, "file://")

	var artifactFile string
	err := filepath.Walk(filepath.Join(dir, "v1", "artifacts"), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			artifactFile = path
		}
		return err
	})
	if err != nil || artifactFile == "" {
		t.Fatalf("locating the vendored artifact: %v", err)
	}
	if err := os.WriteFile(artifactFile, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := NewClient(source)
	descriptor, err := c.FetchCircuit(t.Context(), "vega-mc-p256-v1-prover-key-r12")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DownloadArtifact(t.Context(), descriptor); err == nil {
		t.Fatal("expected a hash mismatch for an edited vendored artifact")
	}
}

// FetchCircuit's id comes from a presented proof's zkSystemId on the
// verifier side. Against the HTTP service a crafted one reaches some other
// path on the source; against a vendored mirror it is a direct filesystem
// read, where it would escape the mirror entirely.
func TestFetchCircuitRefusesAnIDThatIsNotAnID(t *testing.T) {
	source := writeVendoredMirror(t, []byte("x"))
	dir := strings.TrimPrefix(source, "file://")
	c := NewClient(source)

	// A readable, well-formed descriptor OUTSIDE v1/circuits, so the
	// traversal case below has something to actually reach. Without it the
	// test would pass on "no such file" whether or not anything validated
	// the id - which is how a path-traversal test comes to prove nothing.
	write(t, filepath.Join(dir, "escaped.json"), []byte(`{"id":"escaped","system":"vega-mc","status":"active","published":true}`))

	t.Run("traversal does not escape the mirror", func(t *testing.T) {
		got, err := c.FetchCircuit(t.Context(), "../../escaped")
		if err == nil {
			t.Fatalf("FetchCircuit escaped the mirror and returned %q", got.ID)
		}
		if !strings.Contains(err.Error(), "invalid circuit id") {
			t.Fatalf("error = %v, want the id refused before any read", err)
		}
	})

	for _, id := range []string{
		"../../../etc/passwd",
		"vega/../../etc/passwd",
		"..",
		".",
		"",
		"vega%2f..%2fetc",
		"vega?x=1",
		"vega#frag",
		"vega key",
		"vega\\key",
	} {
		t.Run(id, func(t *testing.T) {
			_, err := c.FetchCircuit(t.Context(), id)
			if err == nil {
				t.Fatalf("FetchCircuit(%q) succeeded; want a refusal", id)
			}
			// Refused as an id, not merely missing: the distinction is the
			// whole point, since "not found" is what an unvalidated id
			// happens to produce when the file is not there.
			if !strings.Contains(err.Error(), "invalid circuit id") {
				t.Errorf("error = %v, want one refusing the id itself", err)
			}
		})
	}
}

// file://host/share is a reference to another machine - a network fetch
// wearing a local scheme, which is not what a vendored mirror is.
func TestFileURLWithARemoteHostIsRefused(t *testing.T) {
	if _, err := fetchFile("file://fileserver.example/mirror/v1/manifest.json", 1024); err == nil {
		t.Fatal("expected a refusal for a file URL naming a host")
	}
	if _, err := fetchFile("file://localhost/definitely/not/here.json", 1024); err == nil {
		t.Fatal("expected an open error, not a host refusal, for localhost")
	}
}

func TestFetchFileBoundsItsRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	write(t, path, make([]byte, 4096))

	if _, err := fetchFile("file://"+filepath.ToSlash(path), 1024); err == nil {
		t.Fatal("expected a refusal for a file over the cap")
	}
	if _, err := fetchFile("file://"+filepath.ToSlash(path), 8192); err != nil {
		t.Fatalf("a file under the cap should read: %v", err)
	}
	if _, err := fetchFile("file://"+filepath.ToSlash(dir), 8192); err == nil {
		t.Fatal("expected a refusal for a directory")
	}
}

// An absolute artifact URL in any scheme but https used to fall through to
// candidateArtifactURLs, which treats a non-http URL as a RELATIVE PATH and
// glues it onto every source - producing a nonsense URL instead of saying
// the catalog had said something unexpected.
func TestDownloadArtifactRefusesANonHTTPSAbsoluteURL(t *testing.T) {
	c := NewClient("https://catalog.example")

	for _, raw := range []string{"file:///etc/passwd", "ftp://host/x", "gopher://host/x"} {
		t.Run(raw, func(t *testing.T) {
			_, err := c.DownloadArtifact(t.Context(), &CircuitDescriptor{
				ID:       "c",
				Artifact: &Artifact{URL: raw, Hash: "sha256:" + strings.Repeat("ab", 32)},
			})
			if err == nil || !strings.Contains(err.Error(), "scheme") {
				t.Fatalf("error = %v, want one naming the scheme", err)
			}
		})
	}
}

// isAllowedAbsoluteHost compared hosts only. A file:// source has an empty
// host, so with one configured every empty-host URL - any scheme at all -
// read as "one of our sources".
func TestAllowedAbsoluteHostComparesTheSchemeToo(t *testing.T) {
	c := NewClient("file:///srv/mirror")

	if c.isAllowedAbsoluteHost("https:///somewhere") {
		t.Error("an https URL must not match a file:// source on an empty host")
	}
	if !c.isAllowedAbsoluteHost("file:///srv/mirror/v1/manifest.json") {
		t.Error("the file source should match itself")
	}
}
