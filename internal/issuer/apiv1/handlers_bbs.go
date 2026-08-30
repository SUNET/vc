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

	if c.bbsKeys == nil {
		return nil, fmt.Errorf("bbs issuance is not configured on this issuer")
	}
	if len(req.Commitment) == 0 {
		return nil, fmt.Errorf("commitment is required")
	}
	if req.VCT == "" {
		return nil, fmt.Errorf("vct is required")
	}

	// Same status list allocation the SD-JWT path performs, and for the
	// same reason: a credential that cannot be revoked is a credential
	// that outlives every reason to withdraw it. It reaches the credential
	// through the issuer header rather than a claim, since a claim would
	// be one of the signed messages and so selectively disclosable - and
	// revocation status a holder can decline to reveal is not revocation.
	if c.registryClient == nil {
		return nil, fmt.Errorf("registry client not configured")
	}
	statusEntry, err := c.registryClient.TokenStatusListAddStatus(ctx, &apiv1_registry.TokenStatusListAddStatusRequest{
		Status: 0, // VALID status for new credential
	})
	if err != nil {
		c.log.Error(err, "failed to get status list entry from registry")
		return nil, fmt.Errorf("failed to allocate status list entry: %w", err)
	}

	extraHeader, err := c.bbsIssuerHeader(statusEntry)
	if err != nil {
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
