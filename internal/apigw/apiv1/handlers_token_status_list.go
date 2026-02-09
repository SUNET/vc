package apiv1

import (
	"context"
	"strconv"

	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/tokenstatuslist"
)

// TokenStatusListsAddRecordRequest represents the request for adding a record to the Token Status List.
// This is an internal API for the issuer to allocate indices for new credentials.
type TokenStatusListsAddRecordRequest struct {
	// Status is the initial status value for the record (0=VALID, 1=INVALID, 2=SUSPENDED)
	// Defaults to 0 (VALID) if not specified
	Status *uint8 `json:"status"`
}

// TokenStatusListsAddRecordResponse represents the response after adding a record to the Token Status List.
type TokenStatusListsAddRecordResponse struct {
	// Section is the section ID where the record was added
	Section int64 `json:"section"`

	// Index is the index within the section for this record
	Index int64 `json:"index"`

	// URI is the full Token Status List URI for the status claim in a Referenced Token
	URI string `json:"uri"`
}

// TokenStatusListsAddRecord handles requests to add a new record to the Token Status List.
// This is an internal API used by the issuer when issuing new credentials.
// It allocates a new index in the current section and returns the section/index pair
// that should be embedded in the Referenced Token's status claim.
//
// Request Body (JSON):
//   - status: Optional. Initial status value (0=VALID, 1=INVALID, 2=SUSPENDED). Defaults to 0.
//
// Response (JSON):
//   - section: The section ID where the record was added
//   - index: The index within the section for this record
//   - uri: The full Token Status List URI for the status claim
func (c *Client) TokenStatusListsAddRecord(ctx context.Context, req *TokenStatusListsAddRecordRequest) (*TokenStatusListsAddRecordResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:TokenStatusListsAddRecord")
	defer span.End()

	c.log.Debug("token_status_lists_add_record", "request", req)

	// Default to VALID status if not specified
	status := uint32(0) // tokenstatuslist.StatusValid
	if req.Status != nil {
		status = uint32(*req.Status)
	}

	// Validate status value (0-2 are the standard values per Section 7.1)
	if status > 2 {
		c.log.Error(nil, "invalid status value", "status", status)
		return nil, tokenstatuslist.ErrInvalidStatusValue
	}

	// Call registry via gRPC to add the status
	grpcReq := &apiv1_registry.TokenStatusListAddStatusRequest{
		Status: status,
	}
	grpcReply, err := c.registryClient.TokenStatusListAddStatus(ctx, grpcReq)
	if err != nil {
		c.log.Error(err, "failed to add status record via registry gRPC")
		return nil, err
	}

	// Build the Token Status List URI (pointing to registry)
	uri := c.cfg.APIGW.RegistryPublicURL + "/statuslists/" + strconv.FormatInt(grpcReply.Section, 10)

	reply := &TokenStatusListsAddRecordResponse{
		Section: grpcReply.Section,
		Index:   grpcReply.Index,
		URI:     uri,
	}

	c.log.Debug("token_status_lists_add_record", "reply", reply)

	return reply, nil
}
