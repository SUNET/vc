package apiv1

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// UniqueCommitmentQuery names a key value of a unique entry.
type UniqueCommitmentQuery struct {
	// Scope is the credential scope.
	Scope string `json:"scope" validate:"required"`
	// Path is the claims path of the entry.
	Path []string `json:"path" validate:"required,min=1"`
	// Key gives a value for each part of the entry's key, in its order.
	Key []KeyValue `json:"key" validate:"required,dive"`
}

// ResetUniqueCommitmentRequest names the key value whose commitment an
// operator resets.
type ResetUniqueCommitmentRequest struct {
	UniqueCommitmentQuery
	// EvidenceRef references the operator's case record of the reset.
	EvidenceRef string `json:"evidence_ref" validate:"required,max=256"`
}

// KeyValue is the value of a key part: Value as the credential carries
// it, or the Inputs a to_wallet part with an hkdf opening derives from.
type KeyValue struct {
	Path   []string `json:"path" validate:"required,min=1"`
	Value  *string  `json:"value,omitempty"`
	Inputs []string `json:"inputs,omitempty"`
}

// UniqueCommitmentLookup tells when the commitment of a key value was
// recorded.
type UniqueCommitmentLookup struct {
	RecordedAt time.Time `json:"recorded_at"`
}

// LookupUniqueCommitment finds the commitment on record for a key value.
func (c *Client) LookupUniqueCommitment(ctx context.Context, query *UniqueCommitmentQuery) (*UniqueCommitmentLookup, error) {
	keys, err := c.recordKeys(query)
	if err != nil {
		return nil, err
	}
	var found *UniqueCommitmentLookup
	for _, key := range keys {
		record, err := c.uniqueCommitmentStore.Find(ctx, key)
		switch {
		case errors.Is(err, db.ErrNoDocuments):
			continue
		case err != nil:
			return nil, err
		}
		if found == nil || record.AcceptedAt.Before(found.RecordedAt) {
			found = &UniqueCommitmentLookup{RecordedAt: record.AcceptedAt}
		}
	}
	if found == nil {
		return nil, noCommitment()
	}
	return found, nil
}

// ResetUniqueCommitment removes the commitment on record for a key value,
// with the operator's approval on record, so the next issuance records a
// new one.
func (c *Client) ResetUniqueCommitment(ctx context.Context, req *ResetUniqueCommitmentRequest, approvedBy string) error {
	keys, err := c.recordKeys(&req.UniqueCommitmentQuery)
	if err != nil {
		return err
	}
	approval := db.UniqueCommitmentReset{ApprovedBy: approvedBy, EvidenceRef: req.EvidenceRef, At: time.Now()}
	reset := 0
	for _, key := range keys {
		err := c.uniqueCommitmentStore.Reset(ctx, key, approval)
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
		return noCommitment()
	}
	return nil
}

func noCommitment() error {
	return helpers.NewErrorDetailsWithStatus("no_commitment", "no commitment is on record for this key value", http.StatusNotFound)
}

// recordKeys returns the record keys the query can name.
func (c *Client) recordKeys(query *UniqueCommitmentQuery) ([]db.UniqueCommitmentKey, error) {
	entry, err := c.uniqueEntry(query)
	if err != nil {
		return nil, err
	}
	hashes, err := c.keyHashes(query.Scope, entry, query.Key)
	if err != nil {
		return nil, err
	}
	keys := make([]db.UniqueCommitmentKey, 0, len(hashes))
	for _, hash := range hashes {
		keys = append(keys, db.UniqueCommitmentKey{Scope: query.Scope, Path: query.Path, KeyHash: hash})
	}
	return keys, nil
}

// uniqueEntry returns the unique entry with the query's path and key.
func (c *Client) uniqueEntry(query *UniqueCommitmentQuery) (model.UniqueEntry, error) {
	key := make([][]string, 0, len(query.Key))
	for _, value := range query.Key {
		key = append(key, value.Path)
	}
	for _, entry := range c.cfg.APIGW.DataSources.UniqueEntries(query.Scope) {
		if slices.Equal(entry.Path, query.Path) && slices.EqualFunc(entry.KeyPaths(), key, slices.Equal[[]string]) {
			return entry, nil
		}
	}
	return model.UniqueEntry{}, helpers.NewErrorDetailsWithStatus("unknown_entry",
		fmt.Sprintf("scope %q has no unique entry %q with key %q", query.Scope, query.Path, key), http.StatusBadRequest)
}

// keyHashes returns the record keys the values can name. A part derived
// with hkdf gives one value per distinct opening of the source scopes.
func (c *Client) keyHashes(scope string, entry model.UniqueEntry, values []KeyValue) ([][]byte, error) {
	candidates := make([][]string, 0, len(entry.Key))
	for i, part := range entry.Key {
		texts, err := c.partTexts(scope, part, values[i])
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
func (c *Client) partTexts(scope string, part model.KeyPart, value KeyValue) ([]string, error) {
	switch {
	case value.Value != nil && value.Inputs == nil:
		return []string{*value.Value}, nil
	case value.Inputs != nil && value.Value == nil && len(part.Openings) > 0:
		return c.derivedTexts(scope, part, value.Inputs)
	}
	return nil, helpers.NewErrorDetailsWithStatus("invalid_key",
		fmt.Sprintf("key part %q takes a value, or inputs where it is a to_wallet entry with an hkdf opening", part.Path), http.StatusBadRequest)
}

// derivedTexts derives a part's commitment from the identifiers with each
// hkdf opening that takes their number.
func (c *Client) derivedTexts(scope string, part model.KeyPart, inputs []string) ([]string, error) {
	meta := c.cfg.GetCredentialMetadata(scope)
	toWallet := entryLike(meta.AuxiliaryDataSupported().ToWallet,
		openid4vci.AuxiliaryDataEntry{Type: openid4vci.AuxiliaryDataTypeHashCommitment, Path: part.Path})
	if toWallet == nil {
		return nil, fmt.Errorf("scope %q: key part %q is no to_wallet entry", scope, part.Path)
	}
	carrier, err := commitmentCarrierOf(meta.Format)
	if err != nil {
		return nil, err
	}
	var texts []string
	for _, opening := range part.Openings {
		if len(opening.Inputs) != len(inputs) {
			continue
		}
		text, err := derivedText(opening, *toWallet, carrier, inputs)
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

// derivedText is the commitment text an hkdf opening derives from inputs,
// as the entry's claim carries it.
func derivedText(opening *primitives.HKDFOpeningArgs, entry openid4vci.AuxiliaryDataEntry, carrier commitmentCarrier, inputs []string) (string, error) {
	raw, err := opening.OpenValues(inputs)
	if errors.Is(err, primitives.ErrInvalidClaimInput) {
		return "", helpers.NewErrorDetailsWithStatus("invalid_key", err.Error(), http.StatusBadRequest)
	}
	if err != nil {
		return "", err
	}
	commitment, err := openid4vci.HashCommitment(entry.Alg, raw)
	if err != nil {
		return "", err
	}
	return carrier.claimText(entry.Encoding, commitment)
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
	Scope string   `json:"scope"`
	Path  []string `json:"path"`
	// Label names the credential and the entry.
	Label string              `json:"label"`
	Key   []ResettableKeyPart `json:"key"`
}

// ResettableKeyPart is a key part as the reset form asks for it.
type ResettableKeyPart struct {
	Path []string `json:"path"`
	// Label names a part the operator enters as the credential carries it.
	Label string `json:"label,omitempty"`
	// Inputs name, in order, the identifiers a part derived with hkdf
	// takes instead.
	Inputs []string `json:"inputs,omitempty"`
}

// ResettableEntries lists the unique entries of scopes.
func ResettableEntries(cfg *model.Cfg, scopes []string) []ResettableEntry {
	entries := []ResettableEntry{}
	if cfg.APIGW == nil {
		return entries
	}
	for _, scope := range scopes {
		meta := cfg.GetCredentialMetadata(scope)
		for _, unique := range cfg.APIGW.DataSources.UniqueEntries(scope) {
			entry := ResettableEntry{Scope: scope, Path: unique.Path, Label: credentialName(meta, scope) + " · " + claimName(meta, unique.Path), Key: []ResettableKeyPart{}}
			for _, part := range unique.Key {
				entry.Key = append(entry.Key, resettableKeyPart(meta, part))
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

// resettableKeyPart labels a key part: by the inputs of its first hkdf
// opening, or by its claim.
func resettableKeyPart(meta *model.CredentialMetadata, part model.KeyPart) ResettableKeyPart {
	if len(part.Openings) == 0 {
		return ResettableKeyPart{Path: part.Path, Label: claimName(meta, part.Path)}
	}
	inputs := make([]string, 0, len(part.Openings[0].Inputs))
	for _, input := range part.Openings[0].Inputs {
		inputs = append(inputs, humanize(input))
	}
	return ResettableKeyPart{Path: part.Path, Inputs: inputs}
}

// credentialName is the credential's display name, or its scope.
func credentialName(meta *model.CredentialMetadata, scope string) string {
	if meta == nil {
		return scope
	}
	if meta.MDDL != nil && len(meta.MDDL.Display) > 0 {
		return meta.MDDL.Display[0].Name
	}
	if vctm := meta.GetVCTM(); vctm != nil && len(vctm.Display) > 0 {
		return vctm.Display[0].Name
	}
	return scope
}

// claimName is the display name the type metadata gives the claim at path,
// or its last segment as words.
func claimName(meta *model.CredentialMetadata, path []string) string {
	if meta != nil && meta.MDDL != nil && len(path) == 2 {
		if display := meta.MDDL.Claims[path[0]][path[1]].Display; len(display) > 0 {
			return display[0].Name
		}
	}
	if meta != nil {
		if claim, ok := meta.GetVCTM().ClaimAt(path); ok && len(claim.Display) > 0 {
			return claim.Display[0].Label
		}
	}
	return humanize(path[len(path)-1])
}

// humanize writes a claim name as words: issuing_country reads "Issuing
// country", and a dotted name reads its last segment.
func humanize(name string) string {
	words := strings.ReplaceAll(name[strings.LastIndex(name, ".")+1:], "_", " ")
	if words == "" {
		return name
	}
	return strings.ToUpper(words[:1]) + words[1:]
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
