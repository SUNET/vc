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
	// StatusListURI is the list the entry lives in.
	StatusListURI string
	// Local reports whether StatusListURI is a list THIS registry issues.
	// When it is false the entry belongs to an external
	// draft-ietf-oauth-status-list service, and this registry can neither
	// read nor change it - Status is meaningless and the admin GUI must
	// not offer to update it.
	Local bool
	// StatusKnown reports whether Status was actually read. Without it a
	// lookup that found nothing is indistinguishable from an entry that is
	// genuinely VALID, because both leave Status at 0.
	StatusKnown bool
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
			Identifier:    doc.Identifier,
			Section:       doc.Section,
			Index:         doc.Index,
			StatusListURI: doc.StatusListURI,
			Local:         c.ownsStatusList(doc.StatusListURI, doc.Section),
		}

		// Only this registry's own lists can be read from its database.
		// Reading an external entry's section/index out of adminDB would
		// report the status of a DIFFERENT credential - the local one that
		// happens to sit at the same coordinates.
		if result.Local && c.adminDB != nil {
			tokenStatusListDoc, err := c.adminDB.FindOne(ctx, doc.Section, doc.Index)
			if err == nil && tokenStatusListDoc != nil {
				result.Status = tokenStatusListDoc.Status
				result.StatusKnown = true
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
	// StatusListURI names the list the entry belongs to. It is REQUIRED:
	// section and index alone do not identify an entry once entries can
	// come from more than one status list, and acting on them alone would
	// write to whichever list this registry happens to own.
	StatusListURI string `form:"status_list_uri" validate:"required,url"`
	// Search parameter to preserve after update
	SearchIdentifier string `form:"search_identifier" validate:"omitempty,max=256,printascii"`
}

// ownsStatusList reports whether uri is a Status List Token THIS registry
// issues for the given section.
//
// Comparison is against the exact URL the allocation reply and the token's
// sub claim are built from, so "owned" means the same thing in all three
// places.
func (c *Client) ownsStatusList(uri string, section int64) bool {
	if uri == "" || c.cfg == nil {
		return false
	}
	local, err := c.cfg.Registry.StatusListURL(section)
	if err != nil {
		return false
	}
	return uri == local
}

// UpdateStatus updates the status of a credential in the Token Status List.
//
// It refuses entries that belong to an external
// draft-ietf-oauth-status-list service. Those have no sections and report
// section 0, so writing them into this registry's database would revoke
// whichever local credential sits at (0, index) while leaving the intended
// credential valid - two wrong outcomes and no error. Revoking them has to
// go to the service that owns the list.
func (c *Client) UpdateStatus(ctx context.Context, req *UpdateStatusRequest) error {
	if c.adminDB == nil {
		return fmt.Errorf("database not configured")
	}

	if !c.ownsStatusList(req.StatusListURI, req.Section) {
		c.log.Error(nil, "refusing to update a status entry this registry does not own",
			"status_list_uri", req.StatusListURI, "section", req.Section, "index", req.Index)
		return fmt.Errorf("status list %q is not issued by this registry; its status must be changed through the service that owns it", req.StatusListURI)
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
