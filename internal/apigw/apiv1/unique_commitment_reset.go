package apiv1

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// ResetUniqueCommitmentRequest names the key value whose commitment an
// operator resets.
type ResetUniqueCommitmentRequest struct {
	// Scope is the credential scope.
	Scope string `json:"scope" validate:"required"`
	// Path is the claims path of the entry.
	Path []string `json:"path" validate:"required,min=1"`
	// Key gives a value for each part of the entry's key, in its order.
	Key []KeyValue `json:"key" validate:"required,dive"`
	// EvidenceRef references the record of the re-identification.
	EvidenceRef string `json:"evidence_ref" validate:"required,max=256"`
}

// KeyValue is the value of a key part: Value as the credential carries
// it, or the Inputs a to_wallet part with an hkdf opening derives from.
type KeyValue struct {
	Path   []string `json:"path" validate:"required,min=1"`
	Value  *string  `json:"value,omitempty"`
	Inputs []string `json:"inputs,omitempty"`
}

// ResetUniqueCommitment removes the commitment on record for a key value,
// with the operator's approval on record, so the next issuance records a
// new one.
func (c *Client) ResetUniqueCommitment(ctx context.Context, req *ResetUniqueCommitmentRequest, approvedBy string) error {
	entry, err := c.uniqueEntry(req)
	if err != nil {
		return err
	}
	keyHashes, err := c.keyHashes(ctx, req.Scope, entry, req.Key)
	if err != nil {
		return err
	}
	approval := db.UniqueCommitmentReset{ApprovedBy: approvedBy, EvidenceRef: req.EvidenceRef, At: time.Now()}
	reset := 0
	for _, keyHash := range keyHashes {
		err := c.uniqueCommitmentStore.Reset(ctx, db.UniqueCommitmentKey{Scope: req.Scope, Path: req.Path, KeyHash: keyHash}, approval)
		switch {
		case errors.Is(err, db.ErrNoDocuments):
			continue
		case errors.Is(err, db.ErrResetEvidenceUsed):
			return helpers.NewErrorDetailsWithStatus("evidence_used", err.Error(), http.StatusConflict)
		case err != nil:
			return err
		}
		reset++
	}
	if reset == 0 {
		return helpers.NewErrorDetailsWithStatus("no_commitment", "no commitment is on record for this key value", http.StatusNotFound)
	}
	return nil
}

// uniqueEntry returns the unique entry with the request's path and key.
func (c *Client) uniqueEntry(req *ResetUniqueCommitmentRequest) (model.UniqueEntry, error) {
	key := make([][]string, 0, len(req.Key))
	for _, value := range req.Key {
		key = append(key, value.Path)
	}
	for _, entry := range c.cfg.APIGW.DataSources.UniqueEntries(req.Scope) {
		if slices.Equal(entry.Path, req.Path) && slices.EqualFunc(entry.KeyPaths(), key, slices.Equal[[]string]) {
			return entry, nil
		}
	}
	return model.UniqueEntry{}, helpers.NewErrorDetailsWithStatus("unknown_entry",
		fmt.Sprintf("scope %q has no unique entry %q with key %q", req.Scope, req.Path, key), http.StatusBadRequest)
}

// keyHashes returns the record keys the values can name. A part derived
// with hkdf gives one value per distinct opening of the source scopes.
func (c *Client) keyHashes(ctx context.Context, scope string, entry model.UniqueEntry, values []KeyValue) ([][]byte, error) {
	candidates := make([][]string, 0, len(entry.Key))
	for i, part := range entry.Key {
		texts, err := c.partTexts(ctx, scope, part, values[i])
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, texts)
	}
	key := entry.KeyPaths()
	var hashes [][]byte
	for _, texts := range combinations(candidates) {
		hash, err := uniqueKeyHash(key, texts)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	return hashes, nil
}

// partTexts returns the texts a key part's value can have.
func (c *Client) partTexts(ctx context.Context, scope string, part model.KeyPart, value KeyValue) ([]string, error) {
	switch {
	case value.Value != nil && value.Inputs == nil:
		return []string{*value.Value}, nil
	case value.Inputs != nil && value.Value == nil && len(part.Openings) > 0:
		return c.derivedTexts(ctx, scope, part, value.Inputs)
	}
	return nil, helpers.NewErrorDetailsWithStatus("invalid_key",
		fmt.Sprintf("key part %q takes a value, or inputs where it is a to_wallet entry with an hkdf opening", part.Path), http.StatusBadRequest)
}

// derivedTexts derives a part's commitment from the identifiers with each
// hkdf opening that takes their number.
func (c *Client) derivedTexts(ctx context.Context, scope string, part model.KeyPart, inputs []string) ([]string, error) {
	toWallet := entryLike(c.cfg.GetCredentialMetadata(scope).AuxiliaryDataSupported().ToWallet,
		openid4vci.AuxiliaryDataEntry{Type: openid4vci.AuxiliaryDataTypeHashCommitment, Path: part.Path})
	if toWallet == nil {
		return nil, fmt.Errorf("scope %q: key part %q is no to_wallet entry", scope, part.Path)
	}
	var texts []string
	for _, opening := range part.Openings {
		if len(opening.Inputs) != len(inputs) {
			continue
		}
		text, err := derivedText(ctx, opening, toWallet.Alg, inputs)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(texts, text) {
			texts = append(texts, text)
		}
	}
	if len(texts) == 0 {
		return nil, helpers.NewErrorDetailsWithStatus("invalid_key",
			fmt.Sprintf("no hkdf opening of key part %q takes %d inputs", part.Path, len(inputs)), http.StatusBadRequest)
	}
	return texts, nil
}

// derivedText is the commitment text an hkdf opening derives from inputs.
func derivedText(ctx context.Context, opening *primitives.HKDFOpeningArgs, alg string, inputs []string) (string, error) {
	raw, err := opening.OpenValues(ctx, inputs)
	if errors.Is(err, primitives.ErrInvalidClaimInput) {
		return "", helpers.NewErrorDetailsWithStatus("invalid_key", err.Error(), http.StatusBadRequest)
	}
	if err != nil {
		return "", err
	}
	commitment, err := seed.Commit(alg, raw)
	if err != nil {
		return "", err
	}
	return commitmentText(commitment), nil
}

// combinations returns every choice of one text per part.
func combinations(candidates [][]string) [][]string {
	combos := [][]string{{}}
	for _, texts := range candidates {
		next := make([][]string, 0, len(combos)*len(texts))
		for _, combo := range combos {
			for _, text := range texts {
				next = append(next, append(slices.Clone(combo), text))
			}
		}
		combos = next
	}
	return combos
}

// ResettableEntry is a unique entry whose commitments an operator can
// reset.
type ResettableEntry struct {
	Scope string              `json:"scope"`
	Path  []string            `json:"path"`
	Key   []ResettableKeyPart `json:"key"`
}

// ResettableKeyPart is a key part. Inputs lists, per hkdf input, the claims
// the source scopes read, where the part derives from identifiers.
type ResettableKeyPart struct {
	Path   []string   `json:"path"`
	Inputs [][]string `json:"inputs,omitempty"`
}

// ResettableEntries lists the unique entries of scopes.
func ResettableEntries(cfg *model.Cfg, scopes []string) []ResettableEntry {
	entries := []ResettableEntry{}
	if cfg.APIGW == nil {
		return entries
	}
	for _, scope := range scopes {
		for _, unique := range cfg.APIGW.DataSources.UniqueEntries(scope) {
			entry := ResettableEntry{Scope: scope, Path: unique.Path, Key: make([]ResettableKeyPart, 0, len(unique.Key))}
			for _, part := range unique.Key {
				entry.Key = append(entry.Key, ResettableKeyPart{Path: part.Path, Inputs: inputClaims(part.Openings)})
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

// inputClaims lists, per position, the claims the openings read.
func inputClaims(openings []*primitives.HKDFOpeningArgs) [][]string {
	var claims [][]string
	for _, opening := range openings {
		for i, input := range opening.Inputs {
			if i == len(claims) {
				claims = append(claims, nil)
			}
			if !slices.Contains(claims[i], input) {
				claims[i] = append(claims[i], input)
			}
		}
	}
	return claims
}

// warnUnresettableCommitments warns at startup for each unique entry when
// no operator can reset its commitments: a reset is approved by an
// authenticated operator, and the admin API authenticates nobody.
func (c *Client) warnUnresettableCommitments() {
	if c.cfg.APIGW.APIServer.APIAuth.Enabled() {
		return
	}
	for _, entry := range ResettableEntries(c.cfg, slices.Sorted(maps.Keys(c.cfg.Common.CredentialMetadata))) {
		c.log.Warn("a commitment that conflicts with the one on record is refused until an operator resets it, "+
			"and a reset needs apigw.api_server.api_auth", "scope", entry.Scope, "path", entry.Path)
	}
}
