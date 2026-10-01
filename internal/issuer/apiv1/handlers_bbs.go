package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/bbs"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// CreateJWPRequest is the request for a blind BBS credential.
//
// The shape differs from CreateCredentialRequest in one telling way: there
// is no JWK. Every other format here binds a credential to a holder key by
// having the wallet prove possession of an ECDSA key and handing the issuer
// its public half. Blind BBS binds inside the commitment, to a Schnorr key
// in the signature's own group, and the proof of possession is verified as
// part of verifying the commitment. So the binding arrives as bytes the
// issuer must check rather than a key it must trust.
type CreateJWPRequest struct {
	DocumentData   []byte   `json:"document_data" validate:"required"`
	Scope          string   `json:"scope" validate:"required"`
	Commitment     []byte   `json:"commitment" validate:"required"`
	HolderPointers []string `json:"holder_pointers"`
	VCT            string   `json:"vct" validate:"required"`
	KeyBinding     bool     `json:"key_binding"`
	// Suite is bbs.Suite as a number - the APIGW resolved the request's
	// wire name before this call, the same way it decoded the commitment.
	Suite uint32 `json:"suite"`
}

// CreateJWPReply is the reply for a blind BBS credential.
type CreateJWPReply struct {
	Data                   []*apiv1_issuer.Credential `json:"data"`
	TokenStatusListSection int64                      `json:"token_status_list_section"`
	TokenStatusListIndex   int64                      `json:"token_status_list_index"`
	// TokenStatusListURI is the list the entry was allocated in. Empty when
	// no status entry was allocated, i.e. the credential is not revocable.
	// Section is meaningful only for vc's own registry backend; an external
	// draft-ietf-oauth-status-list service has no sections and identifies a
	// list by this URI alone.
	TokenStatusListURI string `json:"token_status_list_uri,omitempty"`
	// TokenStatusListBackend names the status-list implementation that
	// issued the entry ("registry" or "status_service"). Recorded at
	// issuance because the URI alone does not identify the backend, and
	// guessing at revocation time writes into the wrong list.
	TokenStatusListBackend string `json:"token_status_list_backend,omitempty"`
	// StatusAllocated says whether an entry was allocated at all, so no
	// caller has to infer it from the other four fields. A registry's
	// first allocation is legitimately section 0, index 0, and "nothing
	// was allocated" is also section 0, index 0 - the URI tells them apart
	// today only because allocateOrDegrade and allocateOptionalStatus both
	// hand the slot back when one arrives without a URI. That is an
	// invariant in another file, and a reader derived from an invariant is
	// a reading that drifts. This is the verdict itself, recorded where
	// the decision is made.
	StatusAllocated bool `json:"status_allocated"`
}

// MakeJWP verifies the holder's commitment and blind-signs a credential.
//
// Exactly one credential comes back, and that is not an oversight to fix
// later. Each of the other formats issues one credential per holder key so
// a wallet gets unlinkable copies; a BBS credential needs no copies, because
// each presentation re-randomises the proof afresh. Issuing a second one
// would need a second commitment and a second blinding factor from the
// wallet, which is a different request, not a longer list.
func (c *Client) MakeJWP(ctx context.Context, req *CreateJWPRequest) (*CreateJWPReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:MakeJWP")
	defer span.End()

	// Explicit codes throughout, so a caller can tell "your request is
	// wrong" from "this deployment cannot do this" without parsing strings.
	// A plain error crosses gRPC as codes.Unknown, which conveys neither.
	if c.bbsKeys == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "bbs issuance is not configured on this issuer")
	}
	if len(req.Commitment) == 0 {
		return nil, grpcstatus.Error(codes.InvalidArgument, "commitment is required")
	}
	if req.VCT == "" {
		return nil, grpcstatus.Error(codes.InvalidArgument, "vct is required")
	}
	// Same reason as the pointer rules below: the issuer's claims become the
	// credential's claim map, so claims that are not a JSON object - or an
	// object with nothing in it - cannot be signed, and finding that out
	// inside the native signer costs a status list entry that is never
	// handed back.
	if err := bbs.ValidateDocumentData(req.DocumentData); err != nil {
		return nil, grpcstatus.Error(codes.InvalidArgument, "document_data "+err.Error())
	}
	// Validated here, not left to bbs.Issue, for the same reason as the
	// availability check below: the status list entry is allocated before
	// signing and never handed back. holder_pointers is entirely
	// caller-controlled - count, syntax and duplicates alike - so a request
	// that cannot possibly be signed would otherwise cost a revocation
	// entry to find that out.
	if err := bbs.ValidateHolderPointers(req.HolderPointers); err != nil {
		return nil, grpcstatus.Error(codes.InvalidArgument, "holder_pointers "+err.Error())
	}
	// The suite the holder built its commitment under, and up here with the
	// other cheap checks for the same reason they are: the status list
	// entry below is allocated before signing and never handed back.
	//
	// Rejecting an unrecognised value matters more than it looks. The zero
	// value is a real suite (plain), so falling through would sign under a
	// domain separation nobody asked for and say nothing - and the wallet
	// would meet it later as "does not verify", which is also what a corrupt
	// commitment and a wrong issuer key say.
	suite := bbs.Suite(req.Suite)
	if suite != bbs.SuitePlain && suite != bbs.SuiteSchnorr {
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "unknown bbs suite %d", req.Suite)
	}
	// "plain" is the suite with no device binding, so a request asking for
	// both is describing two different things.
	if suite == bbs.SuitePlain && req.KeyBinding {
		return nil, grpcstatus.Errorf(codes.InvalidArgument,
			"bbs suite %q has no device binding, but key binding was requested", suite)
	}

	// Same status list allocation the SD-JWT path performs, and for the
	// same reason: a credential that cannot be revoked is a credential
	// that outlives every reason to withdraw it. It reaches the credential
	// through the issuer header rather than a claim, since a claim would
	// be one of the signed messages and so selectively disclosable - and
	// revocation status a holder can decline to reveal is not revocation.
	//
	// A distinct precondition error from "configured but the call failed"
	// below - this is a deployment that never asked for revocation support
	// at all, which a caller cannot fix by retrying.
	if c.statusAllocator == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition,
			"no revocation status allocator configured (set issuer.registry_client or issuer.status_service.ingestion_url)")
	}

	// allocateOrDegrade goes through whichever backend is configured -
	// vc's own built-in Token Status List (registry) or an external
	// draft-ietf-oauth-status-list-21 service - and, only for the external
	// backend with degraded_mode=proceed, returns (nil, nil) instead of an
	// error so the credential is still issued, just without a status
	// entry. See status_allocator.go.
	statusEntry, err := c.allocateOrDegrade(ctx)
	if err != nil {
		c.log.Error(err, "failed to allocate a status list entry")
		// Unavailable, not Internal: the status backend is a separate
		// service and this says nothing about the request, so a caller
		// retrying later is doing the right thing. The wrapped cause stays
		// in the log - returning it would cross gRPC into the APIGW and
		// out of the credential endpoint to a wallet that can do nothing
		// with it.
		return nil, grpcstatus.Error(codes.Unavailable, "could not allocate a revocation entry")
	}

	// The entry above (if any) is now allocated and marked VALID for a
	// credential that does not exist yet, and every path from here that
	// fails leaves it that way. One guard rather than a call at each error
	// site: the sites are what get missed, and three sibling handlers
	// proved it. See releaseUnlessIssued.
	credentialIssued := false
	defer c.releaseUnlessIssued(ctx, statusEntry, &credentialIssued)

	extraHeader, err := c.bbsIssuerHeader(statusEntry)
	if err != nil {
		// Building our own header cannot be anything but our fault, and its
		// error names internal structure. Coarse code, detail to the log.
		c.log.Error(err, "failed to build the bbs issuer header", "scope", req.Scope)
		return nil, grpcstatus.Error(codes.Internal, "failed to issue bbs credential")
	}

	keyBinding := bbs.NoKeyBinding
	if req.KeyBinding {
		keyBinding = bbs.SchnorrKeyBinding
	}

	credential, err := bbs.Issue(c.bbsIssuer(), bbs.IssueParams{
		Suite:          suite,
		SecretKey:      c.bbsKeys.secret,
		PublicKey:      c.bbsKeys.public,
		Commitment:     req.Commitment,
		Vct:            req.VCT,
		DocumentData:   json.RawMessage(req.DocumentData),
		HolderPointers: req.HolderPointers,
		ExtraHeader:    extraHeader,
		KeyBinding:     keyBinding,
	})
	if err != nil {
		// Logged in full, returned coarse. This error crosses gRPC to the
		// APIGW and ends up as the credential endpoint's response, so the
		// wallet is the audience: bbs.ErrVerification's wrapped message is
		// documented as a log-only discriminator that must not reach a
		// relying party, and bbs.ErrInternal means the native layer broke
		// rather than the input being bad. Forwarding either verbatim told
		// a caller which check failed and how - and did it under whatever
		// gRPC code the transport picked by default.
		c.log.Error(err, "failed to issue bbs credential", "scope", req.Scope, "vct", req.VCT)
		switch {
		case errors.Is(err, bbs.ErrVerification):
			return nil, grpcstatus.Error(codes.InvalidArgument, "commitment did not verify")
		default:
			return nil, grpcstatus.Error(codes.Internal, "failed to issue bbs credential")
		}
	}

	reply := &CreateJWPReply{
		Data: []*apiv1_issuer.Credential{
			{
				Credential: credential,
			},
		},
	}
	if statusEntry != nil {
		reply.TokenStatusListSection = statusEntry.Section
		reply.TokenStatusListIndex = statusEntry.Index
		reply.TokenStatusListURI = statusEntry.URI
		reply.TokenStatusListBackend = statusEntry.Backend
		reply.StatusAllocated = true
	}

	credentialIssued = true
	return reply, nil
}

// bbsIssuerHeader builds the issuer header members the container does not
// build for itself.
//
// Only members that must not be selectively disclosable belong here. `iss`
// tells a verifier whose key to check against, and a holder able to withhold
// it could offer a credential no verifier could attribute; the same argument
// applies to validity and revocation. Everything a holder may legitimately
// choose to reveal belongs in the claims instead, where BBS can hide it.
//
// status is nil when issuance is proceeding without a status entry (the
// external status service degraded per degraded_mode=proceed - see
// allocateOrDegrade); the "status" member is then omitted entirely rather
// than sent with a zero index and empty uri, which would read as a real,
// resolvable status_list claim it is not.
func (c *Client) bbsIssuerHeader(status *statusAllocation) (json.RawMessage, error) {
	now := time.Now()
	validity := c.cfg.Issuer.BBS.DefaultValidity
	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}

	header := map[string]any{
		"iss": c.cfg.Issuer.JWTAttribute.Issuer,
		"iat": now.Unix(),
		"exp": now.Add(validity).Unix(),
	}
	if status != nil {
		header["status"] = map[string]any{
			"status_list": map[string]any{
				"idx": status.Index,
				"uri": status.URI,
			},
		}
	}

	encoded, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to encode bbs issuer header: %w", err)
	}
	return encoded, nil
}
