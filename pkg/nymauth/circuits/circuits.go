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
