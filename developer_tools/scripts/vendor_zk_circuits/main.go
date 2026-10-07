// Command vendor_zk_circuits copies circuit catalog entries into a local
// directory laid out exactly like the catalog service itself, so the
// directory can be used as a zk_circuits source with no second code path:
//
//	v1/manifest.json
//	v1/circuits/<id>.json
//	v1/artifacts/sha256/<hex>      (unless -metadata-only)
//
// Point an issuer or verifier at it with
//
//	zk_circuits:
//	  sources: ["file:///etc/vc/zk-circuits"]
//
// Two deployments want this. An ISSUER never runs ZK code - it builds and
// signs the mdoc, the wallet proves and the verifier verifies - so all it
// ever needs is the few-KB descriptors that publish a circuit's wire-shape
// constraints. Run with -metadata-only and the vendored tree is a few
// kilobytes. A VERIFIER does need the artifacts, and an air-gapped or
// reproducible deployment wants the exact bytes it tested against rather
// than whatever the catalog serves on the day.
//
// Nothing is relaxed by vendoring: artifacts are SHA-256 verified against
// their descriptors on the way in here, and verified again by
// zkcircuit.DownloadArtifact on the way out, so a tree edited underneath
// fails exactly the way a tampered download does.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/mdoc/zkcircuit"
)

var version = "n/a"

func main() {
	var (
		source       = flag.String("source", zkcircuit.DefaultZkCircuitURL, "catalog base URL to vendor from")
		outDir       = flag.String("out", "", "directory to write the mirror into (required)")
		system       = flag.String("system", "", "only vendor circuits of this system (e.g. \"vega-mc\"); empty means all")
		docType      = flag.String("doctype", "", "only vendor circuits declaring this doctype; empty means all")
		activeOnly   = flag.Bool("active-only", true, "skip circuits whose status is not \"active\"")
		metadataOnly = flag.Bool("metadata-only", false, "write manifest and descriptors but no artifact bytes (what an issuer needs)")
		timeout      = flag.Duration("timeout", 10*time.Minute, "overall timeout")
		showVersion  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *outDir == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := run(ctx, *source, *outDir, *system, *docType, *activeOnly, *metadataOnly); err != nil {
		fmt.Fprintf(os.Stderr, "vendor_zk_circuits: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, source, outDir, system, docType string, activeOnly, metadataOnly bool) error {
	client := zkcircuit.NewClient(source)

	manifest, err := client.FetchManifest(ctx)
	if err != nil {
		return fmt.Errorf("fetch manifest from %s: %w", source, err)
	}

	selected := selectCircuits(manifest, system, docType, activeOnly)
	if len(selected) == 0 {
		return fmt.Errorf("no circuit in %s matched (system=%q doctype=%q active-only=%v)", source, system, docType, activeOnly)
	}

	if err := os.MkdirAll(filepath.Join(outDir, "v1", "circuits"), 0o755); err != nil {
		return err
	}

	// Rewrite each selected descriptor's artifact URL to the catalog's own
	// relative form before writing it out. An ABSOLUTE url would make a
	// vendored mirror fetch from the original host - which is the one thing
	// a vendored mirror exists to avoid - and zkcircuit refuses an absolute
	// URL whose host is not a configured source anyway, so leaving it would
	// turn into a confusing refusal rather than a local read.
	vendored := make([]zkcircuit.CircuitDescriptor, 0, len(selected))
	for _, c := range selected {
		descriptor := c
		// The manifest is REMOTE DATA and everything here turns it into
		// local paths: one file per entry, named by the catalog's id, plus
		// one per artifact at the catalog's own relative path. An id of
		// "../../../../tmp/owned", or an artifact URL of "../../target",
		// writes outside the mirror. Both are refused by the same rules
		// the client applies.
		if !zkcircuit.ValidCircuitID(descriptor.ID) {
			return fmt.Errorf("catalog returned an unusable circuit id %q - refusing to write it to disk", descriptor.ID)
		}
		if descriptor.Artifact != nil {
			relative, err := artifactPath(descriptor.Artifact)
			if err != nil {
				return fmt.Errorf("circuit %q: %w", descriptor.ID, err)
			}
			artifact := *descriptor.Artifact
			artifact.URL = relative
			descriptor.Artifact = &artifact
		}
		vendored = append(vendored, descriptor)
	}

	for _, descriptor := range vendored {
		path := filepath.Join(outDir, "v1", "circuits", descriptor.ID+".json")
		if err := writeJSON(path, descriptor); err != nil {
			return err
		}
		fmt.Printf("descriptor  %s\n", path)
	}

	out := zkcircuit.Manifest{
		ManifestVersion: manifest.ManifestVersion,
		GeneratedAt:     manifest.GeneratedAt,
		Catalog:         manifest.Catalog,
		Circuits:        vendored,
	}
	manifestPath := filepath.Join(outDir, "v1", "manifest.json")
	if err := writeJSON(manifestPath, out); err != nil {
		return err
	}
	fmt.Printf("manifest    %s (%d circuit(s))\n", manifestPath, len(vendored))

	if metadataOnly {
		fmt.Println("metadata-only: no artifacts written")
		return nil
	}

	// Download from the ORIGINAL descriptors: their artifact URLs still
	// point at the live catalog, which is where the bytes are. The
	// rewritten relative paths above are for the mirror's own consumers.
	for i, descriptor := range selected {
		if descriptor.Artifact == nil {
			fmt.Printf("skip        %s (no artifact)\n", descriptor.ID)
			continue
		}
		data, err := client.DownloadArtifact(ctx, &selected[i])
		if err != nil {
			return fmt.Errorf("download artifact for %q: %w", descriptor.ID, err)
		}
		// Validated above for every selected entry, and again here because
		// this is the call that creates directories and writes bytes.
		relative, err := artifactPath(descriptor.Artifact)
		if err != nil {
			return fmt.Errorf("circuit %q: %w", descriptor.ID, err)
		}
		path := filepath.Join(outDir, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
		fmt.Printf("artifact    %s (%d bytes)\n", path, len(data))
	}

	return nil
}

// selectCircuits filters the manifest the way the flags ask.
func selectCircuits(manifest *zkcircuit.Manifest, system, docType string, activeOnly bool) []zkcircuit.CircuitDescriptor {
	var out []zkcircuit.CircuitDescriptor
	for _, c := range manifest.Circuits {
		if activeOnly && c.Status != zkcircuit.StatusActive {
			continue
		}
		if system != "" && !strings.EqualFold(c.System, system) {
			continue
		}
		if docType != "" && !slicesContains(c.DocTypes, docType) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func slicesContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// artifactPath is the mirror-relative path an artifact is stored at, which
// is the same path zkcircuit resolves against each source when a
// descriptor carries a relative URL or none at all.
//
// An absolute URL is rewritten to the hash-derived path: the mirror's whole
// purpose is to stop pointing at the original host, and zkcircuit refuses
// an absolute URL whose host is not a configured source anyway, so copying
// it through would produce a confusing refusal rather than a local read.
func artifactPath(artifact *zkcircuit.Artifact) (string, error) {
	if artifact.URL != "" && !strings.Contains(artifact.URL, "://") {
		return zkcircuit.SafeRelativeArtifactPath(artifact.URL)
	}
	hash := artifact.Hash
	if i := strings.Index(hash, ":"); i >= 0 {
		hash = hash[i+1:]
	}
	if hash == "" {
		return "", errors.New("artifact has no hash and no usable relative path")
	}
	if !isHex(hash) {
		return "", fmt.Errorf("artifact hash %q is not hexadecimal", artifact.Hash)
	}
	return "v1/artifacts/sha256/" + hash, nil
}

// isHex keeps a hash out of the path unless it really is one. The hash is
// catalog data too, and it is the other half of what builds a file name.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
