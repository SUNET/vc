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
// for a presentation source, the document data otherwise.
func (c *Client) sourceDerivations(scope string, authContext *cache.AuthorizationContext, document map[string]any) ([]primitives.Derivation, map[string]any) {
	if authContext.DataSource == string(model.DataSourcePresentation) {
		accepted := c.cfg.APIGW.DataSources.Presentation.Scopes[scope].From[authContext.PresentedScope]
		return accepted.Derivations, authContext.VerifiedClaims
	}
	return c.cfg.APIGW.DataSources.DerivationsForSource(scope, model.DataSourceType(authContext.DataSource)), document
}

// applyAuxiliaryData writes the commitments of scope's auxiliary_data into
// the document data, and returns it re-encoded with the to_wallet entries
// that carry their openings.
func (c *Client) applyAuxiliaryData(ctx context.Context, scope string, derivations []primitives.Derivation, sourceClaims map[string]any, documentData []byte, fromWallet []openid4vci.AuxiliaryDataEntry) ([]byte, []openid4vci.AuxiliaryDataEntry, error) {
	supported := c.scopeAuxiliaryData(scope)
	commitments, err := walletCommitments(supported.ToIssuer, fromWallet)
	if err != nil {
		return nil, nil, err
	}
	if len(supported.ToWallet) == 0 && len(commitments) == 0 {
		return documentData, nil, nil
	}
	doc, err := newCommitmentDocument(c.cfg.GetCredentialMetadata(scope).Format, documentData)
	if err != nil {
		return nil, nil, fmt.Errorf("scope %q: %w", scope, err)
	}
	toWallet, err := deliverOpenings(ctx, doc, supported.ToWallet, derivations, sourceClaims)
	if err != nil {
		return nil, nil, fmt.Errorf("scope %q: %w", scope, err)
	}
	if err := writeCommitments(doc, commitments); err != nil {
		return nil, nil, err
	}
	out, err := json.Marshal(doc.claims)
	if err != nil {
		return nil, nil, fmt.Errorf("scope %q: %w", scope, err)
	}
	return out, toWallet, nil
}

// scopeAuxiliaryData returns the auxiliary_data of scope's credential
// metadata, empty for a credential without it.
func (c *Client) scopeAuxiliaryData(scope string) openid4vci.AuxiliaryDataSupported {
	meta := c.cfg.GetCredentialMetadata(scope)
	if meta == nil || meta.AuxiliaryData == nil {
		return openid4vci.AuxiliaryDataSupported{}
	}
	return *meta.AuxiliaryData
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
		if err := doc.setCommitment(entry.Path, entry.Encoding, commitment); err != nil {
			return nil, err
		}
		entry.Opening = base64.RawURLEncoding.EncodeToString(opening)
		delivered = append(delivered, entry)
	}
	return delivered, nil
}

// writeCommitments writes each commitment the wallet sent at its path.
func writeCommitments(doc *commitmentDocument, commitments []walletCommitment) error {
	for _, commitment := range commitments {
		if err := doc.setCommitment(commitment.path, commitment.encoding, commitment.value); err != nil {
			return err
		}
	}
	return nil
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

// setCommitment writes a commitment at path, in the entry's encoding.
func (d *commitmentDocument) setCommitment(path []string, encoding string, commitment []byte) error {
	text, err := d.claimText(encoding, commitment)
	if err != nil {
		return fmt.Errorf("path %q: %w", path, err)
	}
	parent, key, err := d.parent(path)
	if err != nil {
		return err
	}
	if existing, present := parent[key]; present && existing != nil {
		return fmt.Errorf("the document data already carries a value at %q", path)
	}
	parent[key] = text
	return nil
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

// walletCommitment is the commitment the wallet sent for a to_issuer entry.
type walletCommitment struct {
	path []string
	// encoding is how the to_issuer entry's claim represents it.
	encoding string
	value    []byte
}

// walletCommitments checks the wallet's entries against the to_issuer
// entries: each entry matches a to_issuer entry, and the wallet sends
// every required one.
func walletCommitments(toIssuer, fromWallet []openid4vci.AuxiliaryDataEntry) ([]walletCommitment, error) {
	commitments := make([]walletCommitment, 0, len(fromWallet))
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
func acceptedCommitment(toIssuer []openid4vci.AuxiliaryDataEntry, entry openid4vci.AuxiliaryDataEntry) (walletCommitment, error) {
	want := entryLike(toIssuer, entry)
	switch {
	case want == nil:
		return walletCommitment{}, invalidAuxiliaryData(fmt.Sprintf("to_issuer of this credential lists no entry for %q", entry.Path))
	case entry.Alg != want.Alg:
		return walletCommitment{}, invalidAuxiliaryData(fmt.Sprintf("the entry for %q must use alg %s", entry.Path, want.Alg))
	}
	value, err := base64.RawURLEncoding.DecodeString(entry.Commitment)
	if err != nil || len(value) != sha256.Size {
		return walletCommitment{}, invalidAuxiliaryData(fmt.Sprintf("the commitment for %q must be a base64url sha-256 hash", entry.Path))
	}
	return walletCommitment{path: entry.Path, encoding: want.Encoding, value: value}, nil
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
