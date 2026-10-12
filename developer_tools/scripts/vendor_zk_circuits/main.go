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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	// Rewrite each selected descriptor's artifact URL to the catalog's own
	// relative form. An ABSOLUTE url would make a vendored mirror fetch
	// from the original host - which is the one thing a vendored mirror
	// exists to avoid - and zkcircuit refuses an absolute URL whose host is
	// not a configured source anyway, so leaving it would turn into a
	// confusing refusal rather than a local read.
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

	// EVERYTHING INTO A STAGING TREE, SWAPPED IN AT THE END.
	//
	// Writing into the live mirror cannot express "this run's selection" as
	// one thing. A descriptor write failing partway leaves some entries
	// replaced and the old manifest still standing; and a narrower rerun -
	// a different -system, or -active-only after the catalog deprecated
	// something - leaves the omitted descriptors in place, still reachable,
	// because the verifier calls FetchCircuit by the id a wallet presents
	// rather than reading the manifest. The mirror then serves a selection
	// nobody asked for.
	//
	// So each run builds a complete tree and swaps it in. Either the whole
	// new selection is published or none of it is, and what the previous
	// run left behind goes with the old tree.
	// outDir first: MkdirTemp wants its parent to exist, so a first run
	// against the documented -out /etc/vc/zk-circuits failed unless
	// somebody had created that leaf by hand.
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating the mirror directory %s: %w", outDir, err)
	}

	fileMode := mirrorFileMode(outDir)

	staging, err := os.MkdirTemp(outDir, ".staging-")
	if err != nil {
		return fmt.Errorf("creating a staging directory under %s: %w", outDir, err)
	}
	defer os.RemoveAll(staging)

	if err := os.MkdirAll(filepath.Join(staging, "v1", "circuits"), dirModeFor(fileMode)); err != nil {
		return err
	}

	// Artifacts first, from the ORIGINAL descriptors: their URLs still
	// point at the live catalog, which is where the bytes are. The
	// rewritten relative paths above are for the mirror's own consumers.
	if !metadataOnly {
		for i, descriptor := range selected {
			if descriptor.Artifact == nil {
				fmt.Printf("skip        %s (no artifact)\n", descriptor.ID)
				continue
			}
			relative, err := artifactPath(descriptor.Artifact)
			if err != nil {
				return fmt.Errorf("circuit %q: %w", descriptor.ID, err)
			}
			stagedPath := filepath.Join(staging, filepath.FromSlash(relative))
			existing := filepath.Join(outDir, filepath.FromSlash(relative))

			// Reuse what the previous run already verified rather than
			// pulling ~130MB again. Only when the bytes on disk still
			// hash to what the descriptor says: a stale or edited file is
			// a download, not a shortcut.
			if reused, err := reuseArtifact(existing, stagedPath, descriptor.Artifact.Hash, fileMode); err != nil {
				return err
			} else if reused {
				fmt.Printf("reused      %s\n", stagedPath)
				continue
			}

			data, err := client.DownloadArtifact(ctx, &selected[i])
			if err != nil {
				return fmt.Errorf("download artifact for %q: %w", descriptor.ID, err)
			}
			if err := writeFileAtomically(stagedPath, data, fileMode); err != nil {
				return err
			}
			fmt.Printf("artifact    %s (%d bytes)\n", stagedPath, len(data))
		}
	}

	// Descriptors, under their canonical id AND each alias.
	//
	// The catalog serves an alias by redirecting to the canonical id and
	// the HTTP client follows that automatically. A file:// source has no
	// redirect: fetchFile opens v1/circuits/<id>.json directly, so an
	// alias that resolves against the live catalog 404s against its own
	// vendored mirror. Writing the alias files is what makes the mirror a
	// faithful copy rather than a subset.
	written := make(map[string]string, len(vendored))
	for _, descriptor := range vendored {
		for _, name := range append([]string{descriptor.ID}, descriptor.Aliases...) {
			if !zkcircuit.ValidCircuitID(name) {
				return fmt.Errorf("circuit %s: alias %q is not a valid circuit id", descriptor.ID, name)
			}
			// Two descriptors claiming one name would make the mirror
			// depend on write order. Refuse rather than pick.
			if owner, clash := written[name]; clash {
				return fmt.Errorf("circuit %s and %s both claim the id or alias %q", owner, descriptor.ID, name)
			}
			written[name] = descriptor.ID

			path := filepath.Join(staging, "v1", "circuits", name+".json")
			if err := writeJSON(path, descriptor, fileMode); err != nil {
				return err
			}
		}
	}

	out := zkcircuit.Manifest{
		ManifestVersion: manifest.ManifestVersion,
		GeneratedAt:     manifest.GeneratedAt,
		Catalog:         manifest.Catalog,
		Circuits:        vendored,
	}
	if err := writeJSON(filepath.Join(staging, "v1", "manifest.json"), out, fileMode); err != nil {
		return err
	}

	if err := swapIn(filepath.Join(staging, "v1"), filepath.Join(outDir, "v1")); err != nil {
		return err
	}

	fmt.Printf("published   %s (%d circuit(s))\n", filepath.Join(outDir, "v1"), len(vendored))
	if metadataOnly {
		fmt.Println("metadata-only: no artifacts written")
	}
	return nil
}

// reuseArtifact copies an already-verified artifact out of the live mirror
// into the staging tree, and reports whether it did.
//
// Verified by hash, not by presence: a file left by an interrupted run, or
// edited since, is a download rather than a shortcut. Reading ~130MB to
// hash it is an order of magnitude cheaper than fetching it again.
func reuseArtifact(existing, staged, expectedHash string, mode os.FileMode) (bool, error) {
	data, err := os.ReadFile(existing)
	if err != nil {
		return false, nil //nolint:nilerr // absent or unreadable means "download it"
	}

	want, ok := sha256HexFromHash(expectedHash)
	if !ok {
		// Not a SHA-256 digest, so there is nothing here to compare
		// against. Download it and let DownloadArtifact refuse it
		// properly, rather than reusing bytes on the strength of a hash
		// in some other algorithm.
		return false, nil
	}

	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return false, nil
	}

	if err := writeFileAtomically(staged, data, mode); err != nil {
		return false, err
	}
	return true, nil
}

// swapIn replaces live with staged, atomically enough that a reader sees
// one complete selection or the other.
//
// Two renames rather than one, because rename onto an existing non-empty
// directory is not allowed. The window where neither is in place is the
// time between two renames in the same directory - microseconds - and the
// alternative, writing into the live tree, has a window the length of the
// whole run.
func swapIn(staged, live string) error {
	retired := ""
	if _, err := os.Stat(live); err == nil {
		retired = live + ".retiring"
		os.RemoveAll(retired)
		if err := os.Rename(live, retired); err != nil {
			return fmt.Errorf("setting aside the previous mirror: %w", err)
		}
	}

	if err := os.Rename(staged, live); err != nil {
		// Put the previous mirror back rather than leaving nothing there.
		if retired != "" {
			_ = os.Rename(retired, live)
		}
		return fmt.Errorf("publishing the new mirror: %w", err)
	}

	if retired != "" {
		_ = os.RemoveAll(retired)
	}
	return nil
}

// selectCircuits filters the manifest the way the flags ask.
func selectCircuits(manifest *zkcircuit.Manifest, system, docType string, activeOnly bool) []zkcircuit.CircuitDescriptor {
	var out []zkcircuit.CircuitDescriptor
	for _, c := range manifest.Circuits {
		// Unpublished is never usable, whatever --active-only says.
		// zkcircuit's own usable set requires BOTH published and active
		// (constraints.go), so vendoring an unpublished descriptor either
		// mirrors something the resolver refuses or - worse for a full
		// run - fails the whole vendoring on an artifact that was never
		// published.
		if !c.Published {
			continue
		}
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
	hash, ok := sha256HexFromHash(artifact.Hash)
	if !ok {
		return "", fmt.Errorf("artifact hash %q is not a SHA-256 digest", artifact.Hash)
	}
	return "v1/artifacts/sha256/" + hash, nil
}

// sha256HexFromHash reads a catalog Artifact.Hash as a SHA-256 digest,
// accepting a bare 64-character hex string or one prefixed "sha256:".
//
// The ALGORITHM is checked, not merely stripped. Taking whatever follows
// the colon let "md5:<64 hex>" through as if it were SHA-256 - comparing a
// SHA-256 sum against an MD5 one, so a reuse would never match and a
// mirror would be published that the client then refuses for the same
// reason. The catalog serves sha256 today; anything else is something this
// tool does not understand and should say so.
func sha256HexFromHash(hash string) (string, bool) {
	if i := strings.Index(hash, ":"); i >= 0 {
		if !strings.EqualFold(hash[:i], "sha256") {
			return "", false
		}
		hash = hash[i+1:]
	}
	if len(hash) != sha256.Size*2 {
		return "", false
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", false
	}
	return hash, true
}

func writeJSON(path string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(path, append(data, '\n'), mode)
}

// writeFileAtomically writes to a temporary name in the destination
// directory and renames it into place, so a reader pointed at this mirror
// never sees a half-written file - and a re-run that fails partway leaves
// the previous version of each file intact rather than a truncated one.
//
// mode comes from mirrorFileMode rather than a constant here; see its doc
// comment for why the mirror's own directory decides.
func writeFileAtomically(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirModeFor(mode)); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".vendor-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	// CreateTemp always makes 0600 and ignores the umask, so without this
	// the mirror would be readable only by whoever ran the tool - which is
	// usually not the user the verifier runs as.
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// mirrorFileMode decides what mode the mirror's files get, by reading the
// mode of the directory the operator gave us.
//
// Not a constant, and not the umask either. os.CreateTemp hardcodes 0600
// and ignores the umask, so something has to set the mode explicitly - and
// a hardcoded 0644 imposes this tool's opinion on a tree somebody else
// owns. A mirror served to another user wants group or world read; one on
// a single-user host does not; and the operator has already said which by
// creating (or not creating) the output directory.
//
// So the directory decides: its permission bits, minus execute, which is
// the ordinary relationship between a directory and the files in it. An
// operator who wants 0640 creates the directory 0750 and gets it. The
// default path - this tool creating the directory itself at 0755 - yields
// 0644, which is what it always did.
//
// A directory that cannot be read falls back to 0600: the tightest mode,
// not the loosest, since the one thing worse than a mirror the service
// cannot read is one anybody can rewrite.
func mirrorFileMode(dir string) os.FileMode {
	info, err := os.Stat(dir)
	if err != nil {
		return 0o600
	}
	mode := info.Mode().Perm() &^ 0o111
	if mode&0o444 == 0 {
		return 0o600
	}
	return mode
}

// dirModeFor is the directory mode matching a file mode: the same bits,
// plus execute wherever read is allowed, since a directory has to be
// traversable by whoever may read what is in it.
func dirModeFor(mode os.FileMode) os.FileMode {
	dir := mode
	for _, read := range []os.FileMode{0o400, 0o040, 0o004} {
		if mode&read != 0 {
			dir |= read >> 2
		}
	}
	return dir
}
