package apiv1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// Credential Auxiliary Data
// (openid-4-verifiable-credential-issuance-auxiliary-data.md in
// sirosfoundation/nym_auth_rulebook).

// sourceDerivations returns the derivations of the data source this
// issuance uses, and the claims they read: the verified presented claims
// for a presentation source, source otherwise.
func (c *Client) sourceDerivations(scope string, authContext *cache.AuthorizationContext, source map[string]any) ([]primitives.Derivation, map[string]any) {
	if authContext.DataSource == string(model.DataSourcePresentation) {
		accepted := c.cfg.APIGW.DataSources.Presentation.Scopes[scope].From[authContext.PresentedScope]
		return accepted.Derivations, storedClaims(authContext.VerifiedClaims)
	}
	return c.cfg.APIGW.DataSources.DerivationsForSource(scope, model.DataSourceType(authContext.DataSource)), source
}

// openingSourceClaims returns the claims an opening reads for a source other
// than a presentation, as the source supplied them: a datastore or external
// API document before its derivations run, and for an assertion the claims
// the callback captured before it derived and filtered them. A document
// cached without them gives its document data.
func openingSourceClaims(authContext *cache.AuthorizationContext, document *model.CompleteDocument) map[string]any {
	if authContext.DataSource == string(model.DataSourceAssertion) && len(document.OpeningClaims) > 0 {
		return document.OpeningClaims
	}
	return document.DocumentData
}

// storedClaims is claims as plain maps and slices: a Mongo-backed store
// returns nested objects as bson.D, which dotted claim paths cannot walk.
func storedClaims(claims map[string]any) map[string]any {
	normalised, _ := normalizeBSONValue(claims).(map[string]any)
	return normalised
}

// appliedAuxiliaryData is what scope's auxiliary_data makes of an
// issuance.
type appliedAuxiliaryData struct {
	// documentData is the document data with the commitments.
	documentData []byte
	// toWallet are the to_wallet entries with their openings.
	toWallet []openid4vci.AuxiliaryDataEntry
	// unique are the commitments VCICredential records once the request
	// has passed its checks.
	unique []uniqueCommitment
}

// applyAuxiliaryData writes the commitments of scope's auxiliary_data into
// the document data. A to_issuer path holds the commitment the wallet sent,
// or nothing.
func (c *Client) applyAuxiliaryData(ctx context.Context, scope string, derivations []primitives.Derivation, sourceClaims map[string]any, documentData []byte, fromWallet []openid4vci.AuxiliaryDataEntry) (appliedAuxiliaryData, error) {
	supported := c.cfg.GetCredentialMetadata(scope).AuxiliaryDataSupported()
	commitments, err := walletCommitments(supported.ToIssuer, fromWallet)
	if err != nil {
		return appliedAuxiliaryData{}, err
	}
	if len(supported.ToWallet) == 0 && len(supported.ToIssuer) == 0 {
		return appliedAuxiliaryData{documentData: documentData}, nil
	}
	doc, err := newCommitmentDocument(c.cfg.GetCredentialMetadata(scope).Format, documentData)
	if err != nil {
		return appliedAuxiliaryData{}, fmt.Errorf("scope %q: %w", scope, err)
	}
	toWallet, err := deliverOpenings(ctx, doc, supported.ToWallet, derivations, sourceClaims)
	if err != nil {
		return appliedAuxiliaryData{}, fmt.Errorf("scope %q: %w", scope, err)
	}
	if err := writeCommitments(doc, commitments); err != nil {
		return appliedAuxiliaryData{}, err
	}
	clearUnsent(doc, supported.ToIssuer, fromWallet)
	unique, err := uniqueCommitments(scope, derivations, supported, doc)
	if err != nil {
		return appliedAuxiliaryData{}, err
	}
	out, err := json.Marshal(doc.claims)
	if err != nil {
		return appliedAuxiliaryData{}, fmt.Errorf("scope %q: %w", scope, err)
	}
	return appliedAuxiliaryData{documentData: out, toWallet: toWallet, unique: unique}, nil
}

// deliverOpenings fulfils each to_wallet entry with the source's
// hash_commitment derivation, and returns the entries with their openings.
func deliverOpenings(ctx context.Context, doc *commitmentDocument, entries []openid4vci.AuxiliaryDataEntry, derivations []primitives.Derivation, sourceClaims map[string]any) ([]openid4vci.AuxiliaryDataEntry, error) {
	delivered := make([]openid4vci.AuxiliaryDataEntry, 0, len(entries))
	for _, entry := range entries {
		hc := primitives.HashCommitmentFor(derivations, entry.Path)
		if hc == nil {
			return nil, fmt.Errorf("no hash_commitment derivation fulfils to_wallet path %q", entry.Path)
		}
		opening, err := hc.NewOpening(sourceClaims)
		if err != nil {
			return nil, fmt.Errorf("to_wallet path %q: %w", entry.Path, err)
		}
		commitment, err := openid4vci.HashCommitment(entry.Alg, opening)
		if err != nil {
			return nil, err
		}
		if err := doc.setCommitment(entry.Path, entry.Encoding, commitment, false); err != nil {
			return nil, err
		}
		delivered = append(delivered, openid4vci.AuxiliaryDataEntry{
			Type:    entry.Type,
			Alg:     entry.Alg,
			Path:    entry.Path,
			Opening: base64.RawURLEncoding.EncodeToString(opening),
		})
	}
	return delivered, nil
}

// uniqueCommitment is the commitment of a unique entry, under the record
// key of its key value.
type uniqueCommitment struct {
	key        db.UniqueCommitmentKey
	commitment []byte
	// fromWallet is true for a to_issuer entry, whose commitment the wallet
	// sent, and false for a to_wallet entry, whose commitment the issuer
	// derived.
	fromWallet bool
}

// uniqueCommitments returns the commitment doc carries for each entry that
// its hash_commitment derivation makes unique. An optional to_issuer entry
// the wallet did not send carries none.
func uniqueCommitments(scope string, derivations []primitives.Derivation, supported openid4vci.AuxiliaryDataSupported, doc *commitmentDocument) ([]uniqueCommitment, error) {
	var unique []uniqueCommitment
	for _, d := range derivations {
		hc := d.HashCommitment
		if hc == nil || hc.Unique == nil {
			continue
		}
		commitment, present := doc.writtenAt(hc.Path)
		if !present {
			continue
		}
		u, err := newUniqueCommitment(scope, hc, commitment, supported, doc)
		if err != nil {
			return nil, err
		}
		unique = append(unique, u)
	}
	return unique, nil
}

// newUniqueCommitment is commitment under the record key of the key value
// doc carries for hc.
func newUniqueCommitment(scope string, hc *primitives.HashCommitmentArgs, commitment []byte, supported openid4vci.AuxiliaryDataSupported, doc *commitmentDocument) (uniqueCommitment, error) {
	fromWallet, err := sentByWallet(supported, hc.Path)
	if err != nil {
		return uniqueCommitment{}, fmt.Errorf("scope %q: %w", scope, err)
	}
	texts, err := keyTexts(doc, hc.Unique.Key)
	if err != nil {
		return uniqueCommitment{}, fmt.Errorf("scope %q: %w", scope, err)
	}
	keyHash, err := uniqueKeyHash(hc.Unique.Key, texts)
	if err != nil {
		return uniqueCommitment{}, err
	}
	return uniqueCommitment{
		key:        db.UniqueCommitmentKey{Scope: scope, Path: hc.Path, KeyHash: keyHash},
		commitment: commitment,
		fromWallet: fromWallet,
	}, nil
}

// sentByWallet reports whether the entry at path is a to_issuer entry,
// whose commitment the wallet sends, or a to_wallet entry.
func sentByWallet(supported openid4vci.AuxiliaryDataSupported, path []string) (bool, error) {
	like := openid4vci.AuxiliaryDataEntry{Type: openid4vci.AuxiliaryDataTypeHashCommitment, Path: path}
	switch {
	case entryLike(supported.ToIssuer, like) != nil:
		return true, nil
	case entryLike(supported.ToWallet, like) != nil:
		return false, nil
	}
	return false, fmt.Errorf("path %q is no auxiliary_data entry of the credential", path)
}

// recordUniqueCommitments records each unique commitment for its key value
// (section 6.4, step 5), or none. Another commitment on record for a key
// value refuses the request. A to_issuer entry is the wallet's, so that is
// auxiliary_data_conflict (section 6.4, steps 1 and 5). A to_wallet entry is
// the issuer's own value, so the request is denied (OpenID4VCI 1.0 section
// 8.3.1.2).
func (c *Client) recordUniqueCommitments(ctx context.Context, unique []uniqueCommitment) error {
	if len(unique) == 0 {
		return nil
	}
	commitments := make([]db.UniqueCommitment, 0, len(unique))
	for _, u := range unique {
		commitments = append(commitments, db.UniqueCommitment{Key: u.key, Commitment: u.commitment})
	}
	err := c.uniqueCommitmentStore.Accept(ctx, commitments, time.Now())
	var conflict *db.UniqueCommitmentConflict
	switch {
	case err == nil:
		return nil
	case !errors.As(err, &conflict):
		return fmt.Errorf("scope %q: %w", unique[0].key.Scope, err)
	case conflict.Index < 0 || conflict.Index >= len(unique):
		return fmt.Errorf("scope %q: the store names commitment %d of %d", unique[0].key.Scope, conflict.Index, len(unique))
	}
	u := unique[conflict.Index]
	code := openid4vci.ErrCredentialRequestDenied
	if u.fromWallet {
		code = openid4vci.ErrAuxiliaryDataConflict
	}
	return &openid4vci.Error{
		Err:              code,
		ErrorDescription: fmt.Sprintf("auxiliary_data: another commitment for %q is on record; an operator-approved reset replaces it", u.key.Path),
	}
}

// keyTexts returns the text of each key part's value in doc.
func keyTexts(doc *commitmentDocument, key [][]string) ([]string, error) {
	texts := make([]string, 0, len(key))
	for _, part := range key {
		value, present := doc.claim(part)
		if !present {
			return nil, fmt.Errorf("the credential carries no value at unique key part %q", part)
		}
		text, err := keyText(value)
		if err != nil {
			return nil, fmt.Errorf("unique key part %q: %w", part, err)
		}
		texts = append(texts, text)
	}
	return texts, nil
}

// keyText is a key part's value as an operator enters it: a string as it
// is, any other value as JSON.
func keyText(value any) (string, error) {
	if text, ok := value.(string); ok {
		return text, nil
	}
	encoded, err := json.Marshal(value)
	return string(encoded), err
}

// uniqueKeyHash is the record key of a key value: SHA-256 of the key's
// paths and the texts of their values, JSON-encoded. Each key of an entry
// has its own records.
func uniqueKeyHash(key [][]string, texts []string) ([]byte, error) {
	encoded, err := json.Marshal([]any{key, texts})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	return sum[:], nil
}

// writeCommitments writes each commitment the wallet sent at its path.
func writeCommitments(doc *commitmentDocument, commitments []pathCommitment) error {
	for _, commitment := range commitments {
		if err := doc.setCommitment(commitment.path, commitment.encoding, commitment.value, true); err != nil {
			return err
		}
	}
	return nil
}

// clearUnsent removes the value doc holds at each to_issuer path the wallet
// sent no entry for.
func clearUnsent(doc *commitmentDocument, toIssuer, fromWallet []openid4vci.AuxiliaryDataEntry) {
	for _, entry := range toIssuer {
		if entryLike(fromWallet, entry) == nil {
			doc.clear(entry.Path)
		}
	}
}

// commitmentCarrier is how a credential format carries a commitment in
// its document data.
type commitmentCarrier struct {
	// mdoc keys a claim by its element identifier, and carries bytes as
	// the standard base64 the mso_mdoc signer decodes into a bstr. A
	// JSON-based credential nests a claim at its path, and its claims
	// hold text.
	mdoc bool
}

// commitmentCarrierOf returns how a credential format carries a
// commitment.
func commitmentCarrierOf(format string) (commitmentCarrier, error) {
	switch {
	case format == openid4vp.FormatMsoMdoc:
		return commitmentCarrier{mdoc: true}, nil
	case openid4vp.IsSDJWTVCCredentialFormat(format):
		return commitmentCarrier{}, nil
	}
	return commitmentCarrier{}, fmt.Errorf("a %q credential carries no hash commitment", format)
}

// claimText is a commitment as the claim represents it: text in the
// entry's encoding, or the bytes.
func (c commitmentCarrier) claimText(encoding string, commitment []byte) (string, error) {
	switch {
	case encoding != "":
		return openid4vci.EncodeCommitment(encoding, commitment)
	case c.mdoc:
		return base64.StdEncoding.EncodeToString(commitment), nil
	}
	return "", errors.New("a claim of a JSON-based credential holds text, so the entry needs an encoding")
}

// commitmentDocument is a credential's document data, with the way its
// format carries a commitment.
type commitmentDocument struct {
	commitmentCarrier
	claims map[string]any
	// written holds the commitments set on the document.
	written []pathCommitment
}

func newCommitmentDocument(format string, documentData []byte) (*commitmentDocument, error) {
	carrier, err := commitmentCarrierOf(format)
	if err != nil {
		return nil, err
	}
	claims, err := decodeDocumentData(documentData)
	if err != nil {
		return nil, err
	}
	return &commitmentDocument{commitmentCarrier: carrier, claims: claims}, nil
}

// setCommitment writes a commitment at path, in the entry's encoding. A
// value already there is a server fault, unless the wallet sent the
// commitment: then an equal value stands, and a different one is a
// conflict the wallet can see.
func (d *commitmentDocument) setCommitment(path []string, encoding string, commitment []byte, fromWallet bool) error {
	text, err := d.claimText(encoding, commitment)
	if err != nil {
		return fmt.Errorf("path %q: %w", path, err)
	}
	parent, key, err := d.parent(path)
	if err != nil {
		return err
	}
	if existing, present := parent[key]; present && existing != nil {
		if !fromWallet {
			return fmt.Errorf("the document data already carries a value at %q", path)
		}
		if existing != text {
			return &openid4vci.Error{Err: openid4vci.ErrAuxiliaryDataConflict, ErrorDescription: fmt.Sprintf("auxiliary_data: the issuer holds a different commitment for %q", path)}
		}
	}
	parent[key] = text
	d.written = append(d.written, pathCommitment{path: path, encoding: encoding, value: commitment})
	return nil
}

// writtenAt returns the commitment set on the document at path.
func (d *commitmentDocument) writtenAt(path []string) ([]byte, bool) {
	i := slices.IndexFunc(d.written, func(w pathCommitment) bool { return slices.Equal(w.path, path) })
	if i < 0 {
		return nil, false
	}
	return d.written[i].value, true
}

// parent returns the object that holds the claim at path, and the claim's
// key in it, creating the objects a nested path passes through.
func (d *commitmentDocument) parent(path []string) (map[string]any, string, error) {
	key := path[len(path)-1]
	if d.mdoc {
		return d.claims, key, nil
	}
	node := d.claims
	for _, segment := range path[:len(path)-1] {
		switch child := node[segment].(type) {
		case map[string]any:
			node = child
		case nil:
			created := map[string]any{}
			node[segment] = created
			node = created
		default:
			return nil, "", fmt.Errorf("the document data carries no object at %q of %q", segment, path)
		}
	}
	return node, key, nil
}

// clear removes the claim at path.
func (d *commitmentDocument) clear(path []string) {
	key := path[len(path)-1]
	if d.mdoc {
		delete(d.claims, key)
		return
	}
	node := d.claims
	for _, segment := range path[:len(path)-1] {
		child, ok := node[segment].(map[string]any)
		if !ok {
			return
		}
		node = child
	}
	delete(node, key)
}

// claim returns the value of the claim at path.
func (d *commitmentDocument) claim(path []string) (any, bool) {
	if d.mdoc {
		value := d.claims[path[len(path)-1]]
		return value, value != nil
	}
	var node any = d.claims
	for _, segment := range path {
		object, ok := node.(map[string]any)
		if !ok {
			return nil, false
		}
		node = object[segment]
	}
	return node, node != nil
}

// decodeDocumentData reads the document, preserving numbers exactly.
func decodeDocumentData(documentData []byte) (map[string]any, error) {
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(documentData))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("document data: %w", err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	return doc, nil
}

// auxiliaryDataExtractor is a key proof that can carry auxiliary_data.
type auxiliaryDataExtractor interface {
	ExtractAuxiliaryData() ([]openid4vci.AuxiliaryDataEntry, error)
}

// keyProofs returns the request's jwt or attestation key proofs.
func keyProofs(req *openid4vci.CredentialRequest) []auxiliaryDataExtractor {
	switch {
	case req.Proof != nil && req.Proof.ProofType == "jwt":
		return []auxiliaryDataExtractor{openid4vci.ProofJWTToken(req.Proof.JWT)}
	case req.Proofs == nil:
		return nil
	case req.Proofs.ProofType() == "jwt":
		return asAuxiliaryDataExtractors(req.Proofs.JWT)
	case req.Proofs.ProofType() == "attestation":
		return asAuxiliaryDataExtractors(req.Proofs.Attestation)
	default:
		return nil
	}
}

func asAuxiliaryDataExtractors[P auxiliaryDataExtractor](proofs []P) []auxiliaryDataExtractor {
	out := make([]auxiliaryDataExtractor, 0, len(proofs))
	for _, proof := range proofs {
		out = append(out, proof)
	}
	return out
}

// walletAuxiliaryData returns the auxiliary_data of the request's key
// proofs, which VCICredential has verified. Every proof must carry the same
// entries.
func walletAuxiliaryData(req *openid4vci.CredentialRequest) ([]openid4vci.AuxiliaryDataEntry, error) {
	var agreed []openid4vci.AuxiliaryDataEntry
	for i, proof := range keyProofs(req) {
		entries, err := proof.ExtractAuxiliaryData()
		if err != nil {
			return nil, invalidAuxiliaryData(err.Error())
		}
		if i > 0 && !reflect.DeepEqual(entries, agreed) {
			return nil, invalidAuxiliaryData("the key proofs carry different auxiliary_data")
		}
		agreed = entries
	}
	return agreed, nil
}

// pathCommitment is a commitment, the claims path the credential carries
// it at, and how that claim represents it.
type pathCommitment struct {
	path []string
	// encoding is the entry's encoding of the commitment.
	encoding string
	value    []byte
}

// walletCommitments checks the wallet's entries against the to_issuer
// entries: each entry matches a to_issuer entry, and the wallet sends
// every required one.
func walletCommitments(toIssuer, fromWallet []openid4vci.AuxiliaryDataEntry) ([]pathCommitment, error) {
	commitments := make([]pathCommitment, 0, len(fromWallet))
	for _, entry := range fromWallet {
		commitment, err := acceptedCommitment(toIssuer, entry)
		if err != nil {
			return nil, err
		}
		commitments = append(commitments, commitment)
	}
	for _, want := range toIssuer {
		if want.Required && entryLike(fromWallet, want) == nil {
			return nil, invalidAuxiliaryData(fmt.Sprintf("the entry for %q is required", want.Path))
		}
	}
	return commitments, nil
}

// acceptedCommitment returns the commitment of a wallet entry that matches
// the to_issuer entry at its path in type and alg.
func acceptedCommitment(toIssuer []openid4vci.AuxiliaryDataEntry, entry openid4vci.AuxiliaryDataEntry) (pathCommitment, error) {
	want := entryLike(toIssuer, entry)
	switch {
	case want == nil:
		return pathCommitment{}, invalidAuxiliaryData(fmt.Sprintf("to_issuer of this credential lists no entry for %q", entry.Path))
	case entry.Alg != want.Alg:
		return pathCommitment{}, invalidAuxiliaryData(fmt.Sprintf("the entry for %q must use alg %s", entry.Path, want.Alg))
	}
	value, err := base64.RawURLEncoding.DecodeString(entry.Commitment)
	if err != nil || len(value) != sha256.Size {
		return pathCommitment{}, invalidAuxiliaryData(fmt.Sprintf("the commitment for %q must be a base64url sha-256 hash", entry.Path))
	}
	return pathCommitment{path: entry.Path, encoding: want.Encoding, value: value}, nil
}

// entryLike returns the entry of entries with the type and path of like.
func entryLike(entries []openid4vci.AuxiliaryDataEntry, like openid4vci.AuxiliaryDataEntry) *openid4vci.AuxiliaryDataEntry {
	for i := range entries {
		if entries[i].Type == like.Type && slices.Equal(entries[i].Path, like.Path) {
			return &entries[i]
		}
	}
	return nil
}

func invalidAuxiliaryData(description string) error {
	return &openid4vci.Error{Err: openid4vci.ErrInvalidProof, ErrorDescription: "auxiliary_data: " + description}
}
