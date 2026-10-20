// Package circuits resolves which nym_auth circuit build a verifier
// may load, and produces its bytes.
//
// Everything here is cgo-free and has no opinion about proofs: it
// decides WHICH artifact, checks that the artifact is the one the
// operator allowed, and hands over the bytes. Loading them into a
// verifier handle needs the native library and lives behind the
// zknative build tag.
//
// The split is deliberate. The ways to get this wrong - an entry
// naming the wrong configuration, an artifact that is not the one
// allowed, two entries claiming one configuration - are all decidable
// without a circuit, and a package that needs a 1 MB artifact and a C
// toolchain to test is one that gets tested less.
package circuits

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/nymauth"
)

// ErrNoSuchConfig is returned when nothing in the allowlist implements
// the configuration asked for.
//
// A distinct error because it is an ordinary operator state - a
// Verifier that allows ssc being asked for psc - and not a fault.
var ErrNoSuchConfig = errors.New("nymauth: no allowed circuit implements this pseudonym configuration")

// Entry is one resolved allowlist entry: an allowed build, and how to
// get its bytes.
type Entry struct {
	Config        string
	HashCircuitID string
	SigCircuitID  string
	BlockEncHash  uint32
	BlockEncSig   uint32

	// Path is the local artifact, when the entry names one.
	Path string
	// ID is the catalog circuit id, when the entry names one instead.
	ID string

	SHA256 string
	Bytes  int64
}

// Allowlist is the set of builds a Verifier may load, by
// configuration.
type Allowlist struct {
	byConfig map[string]Entry

	mu     sync.Mutex
	loaded map[string][]byte
}

// NewAllowlist checks a configured allowlist and returns it resolved.
//
// At construction, so a deployment whose allowlist cannot be honoured
// fails at startup rather than at the first presentation - where the
// operator would see a refused proof and have no reason to suspect
// the configuration.
func NewAllowlist(cfg model.NymAuthCircuits) (*Allowlist, error) {
	list := &Allowlist{byConfig: make(map[string]Entry, len(cfg.Allow))}

	// The sources, here rather than as a struct tag, so a deployment
	// with nym_auth off is not stopped by a source nothing will read.
	for i, source := range cfg.Sources {
		where := fmt.Sprintf("verifier.nym_auth.circuits.sources[%d]", i)
		parsed, err := url.Parse(source)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a URL: %w", where, source, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			// A catalog is fetched over the network; anything else is
			// a value that will fail at the first fetch, with nothing
			// pointing back at the configuration.
			return nil, fmt.Errorf("%s: %q is not an http(s) URL", where, source)
		}
		if parsed.Host == "" {
			return nil, fmt.Errorf("%s: %q has no host", where, source)
		}
	}

	for i, entry := range cfg.Allow {
		where := fmt.Sprintf("verifier.nym_auth.circuits.allow[%d]", i)

		switch entry.Config {
		case nymauth.ConfigKnownOffenderMatchingSSC, nymauth.ConfigKnownOffenderMatchingPSC:
		default:
			// Refused rather than passed through. The configuration
			// decides the pseudonym's domain separator, so an
			// unrecognised one is a build this code cannot reason
			// about at all.
			return nil, fmt.Errorf("%s: %q is not a known-offender-matching configuration", where, entry.Config)
		}

		if _, clash := list.byConfig[entry.Config]; clash {
			// Two builds for one configuration. Refused rather than
			// resolved by order: both claim to implement the same
			// pseudonym function, only one can be right, and a
			// verifier picking by position would verify against
			// whichever the operator happened to write first.
			return nil, fmt.Errorf("%s: a second circuit is allowed for configuration %q", where, entry.Config)
		}

		if err := checkCircuitID(entry.HashCircuitID, where, "hash_circuit_id"); err != nil {
			return nil, err
		}
		if err := checkCircuitID(entry.SigCircuitID, where, "sig_circuit_id"); err != nil {
			return nil, err
		}
		if entry.HashCircuitID == entry.SigCircuitID {
			return nil, fmt.Errorf("%s: the hash and signature circuit ids are the same, which no real build has", where)
		}
		// Both Ligero parameters, and both non-zero. Dropping the
		// struct tags (they ran whether or not the feature was
		// enabled) moved every field's check here, and a zero
		// block_enc is not a default - it is a parameter the loader
		// compares against its allowed build and refuses, after the
		// artifact has been read and hashed, with a status code that
		// says "bad circuit" and not "you left a number out".
		if entry.BlockEncHash == 0 {
			return nil, fmt.Errorf("%s: block_enc_hash is zero; it is the hash circuit's Ligero parameter and the loader checks it", where)
		}
		if entry.BlockEncSig == 0 {
			return nil, fmt.Errorf("%s: block_enc_sig is zero; it is the signature circuit's Ligero parameter and the loader checks it", where)
		}
		if _, err := hex.DecodeString(entry.ArtifactSHA256); err != nil || len(entry.ArtifactSHA256) != 2*sha256.Size {
			return nil, fmt.Errorf("%s: artifact_sha256 is not a 64-character hex SHA-256", where)
		}
		if entry.ArtifactBytes <= 0 {
			return nil, fmt.Errorf("%s: artifact_bytes must be positive", where)
		}
		if (entry.ArtifactPath == "") == (entry.ArtifactID == "") {
			return nil, fmt.Errorf("%s: name exactly one of artifact_path and artifact_id", where)
		}
		if entry.ArtifactID != "" && len(cfg.Sources) == 0 {
			// An id with nowhere to fetch it from. Refused rather
			// than deferred: the catalog does not publish nym_auth
			// descriptors today, so this is far more likely to be a
			// configuration written against a catalog that does not
			// exist than a source list forgotten.
			return nil, fmt.Errorf("%s: names artifact_id %q but no verifier.nym_auth.circuits.sources are configured", where, entry.ArtifactID)
		}

		list.byConfig[entry.Config] = Entry{
			Config:        entry.Config,
			HashCircuitID: entry.HashCircuitID,
			SigCircuitID:  entry.SigCircuitID,
			BlockEncHash:  entry.BlockEncHash,
			BlockEncSig:   entry.BlockEncSig,
			Path:          entry.ArtifactPath,
			ID:            entry.ArtifactID,
			SHA256:        entry.ArtifactSHA256,
			Bytes:         entry.ArtifactBytes,
		}
	}
	return list, nil
}

func checkCircuitID(value, where, what string) error {
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s: %s is not hex", where, what)
	}
	if value == "" {
		return fmt.Errorf("%s: %s is empty", where, what)
	}
	return nil
}

// Preload reads and checks every LOCAL artifact.
//
// At startup, so a missing file, a wrong length or a wrong digest is a
// refusal to start rather than a refused proof later - which is what
// the configuration check promises and what NewAllowlist alone does
// not do, since it only sees the entry and never the bytes.
//
// Catalog ids are skipped deliberately: nothing resolves one yet, and
// refusing to start over an unresolvable id would be refusing over a
// feature that has not arrived. They are refused at load instead, with
// a message saying so.
func (a *Allowlist) Preload(ctx context.Context) error {
	for config, entry := range a.byConfig {
		if entry.Path == "" {
			continue
		}
		if _, err := a.Artifact(ctx, config); err != nil {
			return err
		}
	}
	return nil
}

// Entry returns the allowed build for a configuration.
func (a *Allowlist) Entry(config string) (Entry, error) {
	entry, ok := a.byConfig[config]
	if !ok {
		return Entry{}, fmt.Errorf("%w: %q", ErrNoSuchConfig, config)
	}
	return entry, nil
}

// Configs names every allowed configuration.
func (a *Allowlist) Configs() []string {
	out := make([]string, 0, len(a.byConfig))
	for config := range a.byConfig {
		out = append(out, config)
	}
	return out
}

// Artifact returns the decompressed circuit bytes for a
// configuration, checked against the allowlist entry and cached.
//
// Cached because a circuit is on the order of a megabyte and is read
// per presentation otherwise; the bytes are immutable once checked, so
// the cache cannot serve anything the first read did not verify.
//
// The checks are the operator's own statement, re-made here rather
// than left to the native loader. The loader does check - it refuses
// an artifact whose length, SHA-256 or parameters do not match its
// entry - but it refuses with a status code, and an operator reading
// "bad circuit" has no way to tell a corrupt download from a wrong
// digest from a stale path.
func (a *Allowlist) Artifact(ctx context.Context, config string) ([]byte, error) {
	entry, err := a.Entry(config)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if cached, ok := a.loaded[config]; ok {
		return cached, nil
	}

	raw, err := a.read(ctx, entry)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != entry.Bytes {
		return nil, fmt.Errorf("nymauth: the circuit artifact for %q is %d bytes; the allowlist says %d",
			config, len(raw), entry.Bytes)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
		return nil, fmt.Errorf("nymauth: the circuit artifact for %q hashes to %s; the allowlist says %s",
			config, got, entry.SHA256)
	}

	if a.loaded == nil {
		a.loaded = map[string][]byte{}
	}
	a.loaded[config] = raw
	return raw, nil
}

// read produces the artifact's bytes, without checking them.
func (a *Allowlist) read(_ context.Context, entry Entry) ([]byte, error) {
	if entry.Path == "" {
		// A catalog id. Nothing resolves one yet, and saying so is
		// better than returning bytes from somewhere unintended: the
		// published catalog carries no nym_auth descriptors, so there
		// is nothing to fetch and no shape to fetch it in.
		return nil, fmt.Errorf("nymauth: circuit %q is configured as catalog id %q, which this build cannot resolve yet; use artifact_path",
			entry.Config, entry.ID)
	}

	file, err := os.Open(entry.Path)
	if err != nil {
		return nil, fmt.Errorf("nymauth: circuit artifact for %q: %w", entry.Config, err)
	}
	defer file.Close()

	// Bounded by the allowlist's own declared length, plus one byte so
	// an artifact that is too LONG is detected rather than silently
	// truncated to the expected size and then hashed.
	raw, err := io.ReadAll(io.LimitReader(file, entry.Bytes+1))
	if err != nil {
		return nil, fmt.Errorf("nymauth: circuit artifact for %q: %w", entry.Config, err)
	}
	return raw, nil
}
