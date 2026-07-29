package apiv1

import (
	"context"
	"fmt"
)

// SearchPersonRequest is the request for searching credential subjects
type SearchPersonRequest struct {
	Identifier string `form:"identifier" validate:"omitempty,max=256,printascii"`
}

// PersonResult represents a credential subject with their Token Status List info and current status
type PersonResult struct {
	Identifier string
	Section    int64
	Index      int64
	Status     uint8
}

// SearchPersonReply is the reply for searching credential subjects
type SearchPersonReply struct {
	Results []*PersonResult
}

// SearchPerson searches for credential subjects by name and/or date of birth
func (c *Client) SearchPerson(ctx context.Context, req *SearchPersonRequest) (*SearchPersonReply, error) {
	if c.credentialSubjects == nil {
		return nil, fmt.Errorf("credential subjects database not configured")
	}

	docs, err := c.credentialSubjects.Search(ctx, req.Identifier)
	if err != nil {
		c.log.Error(err, "Failed to search credential subjects")
		return nil, err
	}

	results := make([]*PersonResult, 0, len(docs))
	for _, doc := range docs {
		result := &PersonResult{
			Identifier: doc.Identifier,
			Section:    doc.Section,
			Index:      doc.Index,
		}

		// Fetch current status from Token Status List
		if c.adminDB != nil {
			tokenStatusListDoc, err := c.adminDB.FindOne(ctx, doc.Section, doc.Index)
			if err == nil && tokenStatusListDoc != nil {
				result.Status = tokenStatusListDoc.Status
			}
		}

		results = append(results, result)
	}

	return &SearchPersonReply{Results: results}, nil
}

// UpdateStatusRequest is the request for updating a credential subject's status
type UpdateStatusRequest struct {
	Section int64 `form:"section" validate:"gte=0"`
	Index   int64 `form:"index" validate:"gte=0"`
	Status  uint8 `form:"status" validate:"gte=0,lte=255"`
	// Search parameter to preserve after update
	SearchIdentifier string `form:"search_identifier" validate:"omitempty,max=256,printascii"`
}

// UpdateStatus updates the status of a credential in the Token Status List
func (c *Client) UpdateStatus(ctx context.Context, req *UpdateStatusRequest) error {
	if c.adminDB == nil {
		return fmt.Errorf("database not configured")
	}

	if err := c.adminDB.UpdateStatus(ctx, req.Section, req.Index, req.Status); err != nil {
		c.log.Error(err, "Failed to update status", "section", req.Section, "index", req.Index, "status", req.Status)
		return err
	}

	// Invalidate the Token Status List cache for this section so changes are reflected
	if c.tokenStatusListIssuer != nil {
		if invalidator, ok := c.tokenStatusListIssuer.(interface{ InvalidateSection(int64) }); ok {
			invalidator.InvalidateSection(req.Section)
		}
	}

	c.log.Info("Status updated", "section", req.Section, "index", req.Index, "status", req.Status)
	return nil
}
