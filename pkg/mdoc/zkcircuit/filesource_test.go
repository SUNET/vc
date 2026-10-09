package zkcircuit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

// A file:// source is read off disk by fetchFile, which takes no ctx; the
// dispatcher has to honour cancellation around it so a local mirror is not
// a weaker cancellation contract than the HTTP path.
func TestFileSourceHonoursContextCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	write(t, path, []byte(`{"circuits":[]}`))
	url := "file://" + filepath.ToSlash(path)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := &Client{}
	if _, err := c.fetchBytesURL(ctx, url, 8192); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled file read: error = %v, want context.Canceled", err)
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

// A descriptor's artifact URL is remote data joined onto every source -
// including, since file:// sources exist, a local directory. "../../x"
// would read outside the mirror entirely, and hash verification only
// happens after the read.
func TestVendoredArtifactURLCannotEscapeTheMirror(t *testing.T) {
	source := writeVendoredMirror(t, []byte("x"))
	dir := strings.TrimPrefix(source, "file://")
	write(t, filepath.Join(filepath.Dir(dir), "outside.bin"), []byte("not yours"))

	c := NewClient(source)
	for _, raw := range []string{
		"../outside.bin",
		"v1/../../outside.bin",
		"/../outside.bin",
		"..",
		"v1/artifacts/../../../outside.bin",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := c.DownloadArtifact(t.Context(), &CircuitDescriptor{
				ID:       "c",
				Artifact: &Artifact{URL: raw, Hash: "sha256:" + strings.Repeat("ab", 32)},
			})
			if err == nil {
				t.Fatalf("DownloadArtifact(%q) succeeded; want a refusal", raw)
			}
			if !strings.Contains(err.Error(), "unusable") {
				t.Fatalf("error = %v, want the URL refused before any read", err)
			}
		})
	}
}

func TestSafeRelativeArtifactPath(t *testing.T) {
	ok := map[string]string{
		"v1/artifacts/sha256/abcd":   "v1/artifacts/sha256/abcd",
		"/v1/artifacts/sha256/abcd":  "v1/artifacts/sha256/abcd",
		"v1/./artifacts/sha256/abcd": "v1/artifacts/sha256/abcd",
		"v1/x/../artifacts/sha/abcd": "v1/artifacts/sha/abcd",
	}
	for in, want := range ok {
		t.Run("ok:"+in, func(t *testing.T) {
			got, err := SafeRelativeArtifactPath(in)
			if err != nil || got != want {
				t.Fatalf("SafeRelativeArtifactPath(%q) = %q, %v; want %q, nil", in, got, err, want)
			}
		})
	}

	for _, in := range []string{
		"", "..", "../x", "v1/../../x", "/../x",
		"https://example.com/x", "file:///etc/passwd",
		"v1/x?y=1", "v1/x#f", "v1\\x",
	} {
		t.Run("refused:"+in, func(t *testing.T) {
			if got, err := SafeRelativeArtifactPath(in); err == nil {
				t.Fatalf("SafeRelativeArtifactPath(%q) = %q; want a refusal", in, got)
			}
		})
	}
}

// URL schemes are case-insensitive. An absolute "HTTPS://..." used to pass
// the scheme check (which lowercases) and then fail the lowercase-only
// prefix test, so it was treated as a RELATIVE path and glued onto every
// source as "https://host/HTTPS://..." - a guaranteed download failure
// wearing a confusing error.
func TestDownloadArtifactHandlesAnUppercaseScheme(t *testing.T) {
	c := NewClient("https://catalog.example")

	_, err := c.DownloadArtifact(t.Context(), &CircuitDescriptor{
		ID:       "c",
		Artifact: &Artifact{URL: "HTTPS://elsewhere.example/x", Hash: "sha256:" + strings.Repeat("ab", 32)},
	})
	if err == nil {
		t.Fatal("expected a refusal for an absolute URL on a host that is not a source")
	}
	if !strings.Contains(err.Error(), "not among this client's configured sources") {
		t.Fatalf("error = %v, want it refused as an off-allowlist absolute URL", err)
	}

	// And an uppercase plaintext scheme is still refused as plaintext.
	_, err = c.DownloadArtifact(t.Context(), &CircuitDescriptor{
		ID:       "c",
		Artifact: &Artifact{URL: "HTTP://catalog.example/x", Hash: "sha256:" + strings.Repeat("ab", 32)},
	})
	if err == nil || !strings.Contains(err.Error(), "plaintext http") {
		t.Fatalf("error = %v, want it refused as plaintext", err)
	}
}

// With no URL the HASH is the whole of the path, and it is catalog data
// like everything else in the descriptor.
func TestArtifactHashCannotBeAPath(t *testing.T) {
	source := writeVendoredMirror(t, []byte("x"))
	c := NewClient(source)

	for _, hash := range []string{
		"sha256:../../../../etc/passwd",
		"sha256:..",
		"sha256:",
		"sha256:nothexatall",
		"sha256:ab", // hex, but not a digest
		"../../etc/passwd",
	} {
		t.Run(hash, func(t *testing.T) {
			_, err := c.DownloadArtifact(t.Context(), &CircuitDescriptor{
				ID:       "c",
				Artifact: &Artifact{Hash: hash},
			})
			if err == nil {
				t.Fatalf("DownloadArtifact with hash %q succeeded; want a refusal", hash)
			}
			// The REFUSAL, not a fetch that happened to fail: every one
			// of these also names a file the mirror does not have, so
			// "an error came back" would pass without any validation at
			// all.
			if !strings.Contains(err.Error(), "not a SHA-256 digest") {
				t.Fatalf("error = %v, want the hash refused before any read", err)
			}
		})
	}
}

// path.Clean is LEXICAL and url.Parse DECODES, so a percent-encoded dot
// segment survives the first and becomes a real one before os.Open.
func TestPercentEncodedTraversalIsRefused(t *testing.T) {
	source := writeVendoredMirror(t, []byte("x"))
	dir := strings.TrimPrefix(source, "file://")
	write(t, filepath.Join(filepath.Dir(dir), "outside.bin"), []byte("not yours"))

	c := NewClient(source)
	for _, raw := range []string{
		"%2e%2e/outside.bin",
		"v1/%2e%2e/%2e%2e/outside.bin",
		"%2E%2E/outside.bin",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := c.DownloadArtifact(t.Context(), &CircuitDescriptor{
				ID:       "c",
				Artifact: &Artifact{URL: raw, Hash: "sha256:" + strings.Repeat("ab", 32)},
			})
			if err == nil {
				t.Fatalf("DownloadArtifact(%q) succeeded; want a refusal", raw)
			}
			// Refused as a path, not reported as a hash mismatch after
			// reading the file outside the mirror - the read IS the
			// vulnerability, and the planted file would never match the
			// digest anyway, so "an error came back" proves nothing.
			if !strings.Contains(err.Error(), "unusable") {
				t.Fatalf("error = %v, want the path refused before any read", err)
			}
		})
	}

	// And the decoded check holds even if something gets past the lexical
	// one: a file URL whose decoded path carries a ".." segment is refused
	// at the point of opening it.
	if _, err := fetchFile("file://"+filepath.ToSlash(dir)+"/v1/%2e%2e/outside.bin", 1024); err == nil {
		t.Fatal("fetchFile followed a percent-encoded dot segment")
	}
}

// URL schemes are case-insensitive. A configured "FILE:///srv/mirror" is a
// valid local source, and a lowercase-only prefix check sent it down the
// HTTP path, where it always failed - the same mistake the artifact-URL
// checks had, in the one place that decides which reader runs at all.
func TestFileSourceSchemeIsCaseInsensitive(t *testing.T) {
	source := writeVendoredMirror(t, []byte("x"))
	upper := "FILE://" + strings.TrimPrefix(source, "file://")

	c := NewClient(upper)
	manifest, err := c.FetchManifest(t.Context())
	if err != nil {
		t.Fatalf("a FILE:// source must be read off disk: %v", err)
	}
	if salt, err := manifest.SaltBytes([]string{"vega-mc"}, "org.iso.18013.5.1.mDL"); err != nil || salt != 32 {
		t.Fatalf("SaltBytes = %d, %v; want 32, nil", salt, err)
	}

	if _, err := c.FetchCircuit(t.Context(), "vega-mc-p256-v1-prover-key-r12"); err != nil {
		t.Errorf("FetchCircuit over a FILE:// source: %v", err)
	}
}

// The regular-file check runs again on the OPEN descriptor.
//
// The Lstat before the open closes the common case; this closes the window
// between the two, where a path can be swapped for a FIFO after it has
// been checked and before it is opened.
func TestFetchFileRechecksTheOpenedDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// A regular file still reads, so the second check is not simply
	// refusing everything.
	data, err := fetchFile("file://"+filepath.ToSlash(path), 1024)
	if err != nil {
		t.Fatalf("a regular file was refused: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Errorf("got %q", data)
	}

	// And a FIFO is refused by whichever check reaches it first.
	fifo := filepath.Join(dir, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := fetchFile("file://"+filepath.ToSlash(fifo), 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("want a not-a-regular-file error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fetchFile blocked on a FIFO instead of refusing it")
	}
}
