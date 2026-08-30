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
	// Same reason as the bound below: the issuer's claims become the
	// credential's claim map, so anything that is not a JSON object cannot
	// be signed - and finding that out inside the native signer costs a
	// status list entry that is never handed back. `null` is rejected with
	// the rest: it unmarshals into a map without complaint but is not an
	// object.
	if len(req.DocumentData) > 0 {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(req.DocumentData, &probe); err != nil || probe == nil {
			return nil, grpcstatus.Error(codes.InvalidArgument, "document_data must be a JSON object")
		}
	}
	// Bounds-checked here, not left to bbs.Issue, for the same reason as
	// the availability check below: the status list entry is allocated
	// before signing and never handed back. holder_pointers is entirely
	// caller-controlled, so a request that cannot possibly be signed would
	// otherwise cost a revocation entry to find that out.
	if len(req.HolderPointers) > bbs.MaxMessages {
		return nil, grpcstatus.Errorf(codes.InvalidArgument,
			"holder_pointers has %d entries, over the %d limit", len(req.HolderPointers), bbs.MaxMessages)
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
	if !bbs.Available() {
		return nil, grpcstatus.Error(codes.Unimplemented, "bbs issuance is not available on this issuer")
	}
	statusEntry, err := c.registryClient.TokenStatusListAddStatus(ctx, &apiv1_registry.TokenStatusListAddStatusRequest{
		Status: 0, // VALID status for new credential
	})
	if err != nil {
		c.log.Error(err, "failed to get status list entry from registry")
		return nil, fmt.Errorf("failed to allocate status list entry: %w", err)
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
		return nil, err
	}

	keyBinding := bbs.NoKeyBinding
	if req.KeyBinding {
		keyBinding = bbs.SchnorrKeyBinding
	}

	credential, err := bbs.Issue(bbs.Native(), bbs.IssueParams{
		Suite:          bbs.SuiteSchnorr,
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
