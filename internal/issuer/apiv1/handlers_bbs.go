package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/bbs"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
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
	if c.registryClient == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "registry client not configured")
	}
	// Checked here rather than left to bbs.Issue's ErrUnavailable, because
	// the status list entry below is allocated before that call and is not
	// handed back when it fails. An issuer configured with BBS keys but
	// built without `-tags bbsnative` would burn one registry entry per
	// request while never issuing anything - a slow leak in the revocation
	// list rather than a visible failure.
	//
	// The question is whether *this client* has a usable signer, not
	// whether the process was built with the native backend: those are the
	// same thing in every deployment and differ only where a signer has
	// been supplied directly.
	if c.bbsIssuerOverride == nil && !bbs.Available() {
		return nil, grpcstatus.Error(codes.Unimplemented, "bbs issuance is not available on this issuer")
	}
	statusEntry, err := c.registryClient.TokenStatusListAddStatus(ctx, &apiv1_registry.TokenStatusListAddStatusRequest{
		Status: 0, // VALID status for new credential
	})
	if err != nil {
		c.log.Error(err, "failed to get status list entry from registry")
		// Unavailable, not Internal: the registry is a separate service and
		// this says nothing about the request, so a caller retrying later
		// is doing the right thing. The wrapped cause stays in the log -
		// returning it would cross gRPC into the APIGW and out of the
		// credential endpoint to a wallet that can do nothing with it.
		return nil, grpcstatus.Error(codes.Unavailable, "could not allocate a revocation entry")
	}

	// The entry above is now allocated and marked VALID for a credential
	// that does not exist yet. Every path from here that fails leaves it
	// that way, so each one hands it back: an entry saying VALID with
	// nothing referencing it is not exploitable - no credential carries
	// that index - but it is a wrong answer sitting in a list whose whole
	// job is answering that question, and it accumulates.
	//
	// Best-effort by construction: the issuance has already failed, and a
	// registry that cannot be reached to invalidate could not have been
	// reached to allocate either. Logged, never returned in place of the
	// real error.
	extraHeader, err := c.bbsIssuerHeader(statusEntry)
	if err != nil {
		c.invalidateStatusEntry(ctx, statusEntry)
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
		c.invalidateStatusEntry(ctx, statusEntry)
		switch {
		case errors.Is(err, bbs.ErrVerification):
			return nil, grpcstatus.Error(codes.InvalidArgument, "commitment did not verify")
		case errors.Is(err, bbs.ErrUnavailable):
			return nil, grpcstatus.Error(codes.Unimplemented, "bbs issuance is not available on this issuer")
		default:
			return nil, grpcstatus.Error(codes.Internal, "failed to issue bbs credential")
		}
	}

	return &CreateJWPReply{
		Data: []*apiv1_issuer.Credential{
			{
				Credential: credential,
			},
		},
		TokenStatusListSection: statusEntry.GetSection(),
		TokenStatusListIndex:   statusEntry.GetIndex(),
	}, nil
}

// invalidateStatusEntry hands back a status list entry allocated for a
// credential that was never issued.
//
// The entry is allocated and marked VALID before signing, so every failure
// after that point leaves a list saying VALID about a credential that does
// not exist. Not exploitable - nothing carries that index - but it is a
// wrong answer sitting in a list whose entire job is answering that
// question, and it accumulates one per failed issuance.
//
// Best-effort by construction, and it has to be: the issuance has already
// failed, and a registry unreachable for this call was reachable for the
// allocation moments ago, so there is nothing better to do than say so.
// Logged, never returned in place of the real error.
func (c *Client) invalidateStatusEntry(ctx context.Context, entry *apiv1_registry.TokenStatusListAddStatusReply) {
	if _, err := c.registryClient.TokenStatusListUpdateStatus(ctx, &apiv1_registry.TokenStatusListUpdateStatusRequest{
		Section: entry.GetSection(),
		Index:   entry.GetIndex(),
		Status:  uint32(tokenstatuslist.StatusInvalid),
	}); err != nil {
		c.log.Error(err, "could not invalidate the status entry of a failed bbs issuance",
			"section", entry.GetSection(), "index", entry.GetIndex())
	}
}

// bbsIssuerHeader builds the issuer header members the container does not
// build for itself.
//
// Only members that must not be selectively disclosable belong here. `iss`
// tells a verifier whose key to check against, and a holder able to withhold
// it could offer a credential no verifier could attribute; the same argument
// applies to validity and revocation. Everything a holder may legitimately
// choose to reveal belongs in the claims instead, where BBS can hide it.
func (c *Client) bbsIssuerHeader(status *apiv1_registry.TokenStatusListAddStatusReply) (json.RawMessage, error) {
	now := time.Now()
	validity := c.cfg.Issuer.BBS.DefaultValidity
	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}

	header := map[string]any{
		"iss": c.cfg.Issuer.JWTAttribute.Issuer,
		"iat": now.Unix(),
		"exp": now.Add(validity).Unix(),
		"status": map[string]any{
			"status_list": map[string]any{
				"idx": status.GetIndex(),
				"uri": status.GetStatusListUri(),
			},
		},
	}

	encoded, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to encode bbs issuer header: %w", err)
	}
	return encoded, nil
}
