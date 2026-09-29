package apiv1

import (
	"context"
	"errors"
	"fmt"

	"github.com/SUNET/vc/internal/apigw/db"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"go.opentelemetry.io/otel/codes"
)

// RevokeCredentialRequest asks for every status-list entry belonging to one
// credential subject to be set to a new status.
type RevokeCredentialRequest struct {
	// Identifier is the credential subject (authentic_source_person_id)
	// whose credentials are being acted on. This is the same identifier
	// issuance recorded the entries under.
	Identifier string `json:"identifier" validate:"required"`
	// Status is the draft-ietf-oauth-status-list value to write. Defaults
	// to INVALID (1) when omitted, which is what "revoke" means; 2 is
	// SUSPENDED and 0 puts a suspended credential back in service.
	Status *uint8 `json:"status,omitempty" validate:"omitempty,lte=255"`
	// StatusListURI and Index, when both given, narrow the operation to a
	// single entry instead of every entry the subject holds. A caller that
	// knows exactly which credential to revoke should say so.
	StatusListURI string `json:"status_list_uri,omitempty" validate:"omitempty,url"`
	Index         *int64 `json:"index,omitempty" validate:"omitempty,gte=0"`

	// Authorize reports whether this caller may revoke an entry issued
	// under a given (authentic source, scope). It is supplied by the HTTP
	// layer and is NOT caller-settable (`json:"-" form:"-"`) - a caller
	// that could set it would be authorizing itself.
	//
	// A PAIR, deliberately, and not two membership lists. Flattening the
	// caller's grants into an allowed-sources list and an allowed-scopes
	// list authorizes their Cartesian product: grants of (SUNET, pid) and
	// (OTHER, ehic) put both values in both lists, so an entry recorded as
	// (SUNET, ehic) would pass although that combination was never granted.
	//
	// The closure also carries the method and path, so a rule that
	// authorizes some other route does not authorize revocation.
	//
	// Nil means no authorization decision can be made, and every entry is
	// refused. Authentication is not authorization: without this, any
	// principal the API auth accepts could revoke ANY subject's credentials
	// just by naming the identifier, which is the caller's own input and
	// establishes nothing.
	Authorize func(authenticSource, scope string) bool `json:"-" form:"-"`
}

// RevokedEntry describes one entry the request acted on.
type RevokedEntry struct {
	StatusListURI string `json:"status_list_uri"`
	Index         int64  `json:"index"`
	Backend       string `json:"backend"`
	Status        uint8  `json:"status"`
}

// RevokeCredentialReply reports what was changed.
type RevokeCredentialReply struct {
	Identifier string          `json:"identifier"`
	Revoked    []*RevokedEntry `json:"revoked"`
}

// RevokeCredential sets the status-list status for a credential subject's
// entries.
//
// The apigw is the front door for this because it is the component that
// knows which entries belong to which subject - it records them at issuance
// in its own store, so this works with or without vc's local registry. The
// write itself goes to the issuer, which is the component configured with
// the status-list backends and routes each entry to the one that allocated
// it (see the issuer's SetCredentialStatus).
//
// It is all-or-nothing in intent but not in effect: each entry is a
// separate call to a separate backend, so a failure partway through leaves
// earlier entries already changed. The error names the entry that failed
// and the reply is withheld, so a retry is safe - writing the same status
// twice is idempotent.
func (c *Client) RevokeCredential(ctx context.Context, req *RevokeCredentialRequest) (*RevokeCredentialReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:RevokeCredential")
	defer span.End()

	if req == nil {
		return nil, errors.New("request is required")
	}
	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	if (req.StatusListURI == "") != (req.Index == nil) {
		return nil, errors.New("status_list_uri and index must be given together: either both, to act on one entry, or neither, to act on every entry the subject holds")
	}

	status := uint8(tokenstatuslist.StatusInvalid)
	if req.Status != nil {
		status = *req.Status
	}

	if c.db == nil || c.db.CredentialStatusColl == nil {
		return nil, errors.New("no credential status store configured, so no credential can be revoked")
	}

	entries, err := c.db.CredentialStatusColl.SearchByIdentifier(ctx, req.Identifier)
	if err != nil {
		c.log.Error(err, "failed to look up credential status entries", "identifier", req.Identifier)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("failed to look up status entries: %w", err)
	}

	reply := &RevokeCredentialReply{Identifier: req.Identifier, Revoked: []*RevokedEntry{}}

	var refused int
	for _, e := range entries {
		if req.StatusListURI != "" && (e.StatusListURI != req.StatusListURI || e.Index != *req.Index) {
			continue
		}
		// An entry the caller is not authorized for is skipped, not
		// reported: telling an unauthorized caller that a subject holds a
		// credential in some other authentic source is itself a disclosure.
		// The count feeds the error below, so the request still fails rather
		// than silently succeeding with nothing done.
		if !c.mayRevoke(req, e) {
			c.log.Info("refusing to revoke an entry outside the caller's authorization",
				"identifier", req.Identifier, "authentic_source", e.AuthenticSource, "scope", e.Scope)
			refused++
			continue
		}
		if _, err := c.issuerClient.SetCredentialStatus(ctx, &apiv1_issuer.SetCredentialStatusRequest{
			Backend:       e.Backend,
			StatusListUri: e.StatusListURI,
			Section:       e.Section,
			Index:         e.Index,
			Status:        uint32(status),
		}); err != nil {
			c.log.Error(err, "failed to set credential status",
				"identifier", req.Identifier, "uri", e.StatusListURI, "index", e.Index, "backend", e.Backend)
			span.SetStatus(codes.Error, err.Error())
			return nil, fmt.Errorf("failed to set status of entry %d in %q: %w", e.Index, e.StatusListURI, err)
		}
		reply.Revoked = append(reply.Revoked, &RevokedEntry{
			StatusListURI: e.StatusListURI,
			Index:         e.Index,
			Backend:       e.Backend,
			Status:        status,
		})
	}

	// Nothing matched. This is not success: the caller asked for a
	// credential's status to change and no status changed, so answering OK
	// would report a revocation that did not happen.
	if len(reply.Revoked) == 0 {
		if refused > 0 {
			return nil, fmt.Errorf("not authorized to revoke any recorded status list entry for identifier %q%s", req.Identifier, narrowedTo(req))
		}
		return nil, fmt.Errorf("no status list entry is recorded for identifier %q%s", req.Identifier, narrowedTo(req))
	}

	c.log.Info("credential status updated", "identifier", req.Identifier, "entries", len(reply.Revoked), "status", status)
	return reply, nil
}

// narrowedTo describes the entry filter in an error message, when there was one.
func narrowedTo(req *RevokeCredentialRequest) string {
	if req.StatusListURI == "" {
		return ""
	}
	return fmt.Sprintf(" at index %d of %q", *req.Index, req.StatusListURI)
}

// mayRevoke reports whether the caller's authorization covers this entry.
//
// The decision is delegated to the HTTP layer's closure so that the
// authentic source and scope are checked as ONE pair against the engine,
// together with the method and path - see RevokeCredentialRequest.Authorize
// for why neither of those can be dropped.
//
// Matching is on the authentic source and scope the entry was ISSUED under,
// recorded at issuance. The subject identifier is not a basis for this
// decision: it is the caller's own input.
//
// A nil Authorize refuses everything. That is the fail-closed reading: a
// caller arrived at a destructive operation with no way to decide whether
// they may perform it.
func (c *Client) mayRevoke(req *RevokeCredentialRequest, e *db.CredentialStatusEntry) bool {
	if req.Authorize == nil {
		return false
	}
	return req.Authorize(e.AuthenticSource, e.Scope)
}
