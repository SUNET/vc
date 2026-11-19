package authzen

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Evaluations semantics (AuthZEN access evaluations API, options.evaluations_semantic).
const (
	// EvaluationsSemanticExecuteAll evaluates every item. This is the default.
	EvaluationsSemanticExecuteAll = "execute_all"
	// EvaluationsSemanticDenyOnFirstDeny stops after the first decision=false.
	EvaluationsSemanticDenyOnFirstDeny = "deny_on_first_deny"
	// EvaluationsSemanticPermitOnFirstPermit stops after the first decision=true.
	EvaluationsSemanticPermitOnFirstPermit = "permit_on_first_permit"
)

// BatchEvaluationItem is one entry of the evaluations array. Members that are
// present replace the request-level default of the same name as a whole; an
// absent member inherits the default.
// @Description One item of a batch evaluation request
type BatchEvaluationItem struct {
	Subject  *Subject               `json:"subject,omitempty"`
	Resource *Resource              `json:"resource,omitempty"`
	Action   *Action                `json:"action,omitempty"`
	Context  map[string]interface{} `json:"context,omitempty" swaggertype:"object,string"`
}

// BatchOptions carries the optional options member of a batch request.
// @Description Options of a batch evaluation request
type BatchOptions struct {
	// EvaluationsSemantic is one of execute_all (default), deny_on_first_deny
	// and permit_on_first_permit.
	EvaluationsSemantic string `json:"evaluations_semantic,omitempty" example:"execute_all"`
}

// BatchEvaluationRequest is the body of POST /evaluations. The top-level
// subject, resource, action and context are defaults shared by all items.
// @Description AuthZEN access evaluations (batch) request
type BatchEvaluationRequest struct {
	Subject  *Subject               `json:"subject,omitempty"`
	Resource *Resource              `json:"resource,omitempty"`
	Action   *Action                `json:"action,omitempty"`
	Context  map[string]interface{} `json:"context,omitempty" swaggertype:"object,string"`
	// Evaluations are kept raw so that a malformed entry fails only itself
	// (see Item) instead of the whole request.
	Evaluations []json.RawMessage `json:"evaluations" swaggertype:"array,object"`
	Options     *BatchOptions     `json:"options,omitempty"`
}

// BatchEvaluationResponse is the body of a POST /evaluations answer: one
// result per evaluated item, in request order. Each result has the shape of a
// POST /evaluation response.
// @Description AuthZEN access evaluations (batch) response
type BatchEvaluationResponse struct {
	Evaluations []EvaluationResponse `json:"evaluations"`
}

// Semantic returns the requested evaluations semantic, or an error for an
// unknown value.
func (r *BatchEvaluationRequest) Semantic() (string, error) {
	if r.Options == nil || r.Options.EvaluationsSemantic == "" {
		return EvaluationsSemanticExecuteAll, nil
	}
	switch s := r.Options.EvaluationsSemantic; s {
	case EvaluationsSemanticExecuteAll, EvaluationsSemanticDenyOnFirstDeny, EvaluationsSemanticPermitOnFirstPermit:
		return s, nil
	default:
		return "", fmt.Errorf("unsupported options.evaluations_semantic %q", s)
	}
}

// Item returns the evaluation request for item i: the item's members over the
// request-level defaults. The Context is a fresh map, because evaluation adds
// server-controlled members to it and items must not see each other's.
// An entry that is not a JSON object, or has a member of the wrong type,
// is an error for that item alone; it never inherits the defaults.
func (r *BatchEvaluationRequest) Item(i int) (*EvaluationRequest, error) {
	raw := bytes.TrimSpace(r.Evaluations[i])
	if len(raw) == 0 || raw[0] != '{' {
		return nil, fmt.Errorf("evaluations[%d] must be an object", i)
	}
	var it BatchEvaluationItem
	if err := json.Unmarshal(raw, &it); err != nil {
		return nil, fmt.Errorf("evaluations[%d] is malformed", i)
	}
	// An explicit null is not "absent": it must not fall back to the default.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("evaluations[%d] is malformed", i)
	}
	for name, v := range members {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, fmt.Errorf("evaluations[%d].%s must not be null", i, name)
		}
	}
	req := &EvaluationRequest{}
	switch {
	case it.Subject != nil:
		req.Subject = *it.Subject
	case r.Subject != nil:
		req.Subject = *r.Subject
	}
	switch {
	case it.Resource != nil:
		req.Resource = *it.Resource
	case r.Resource != nil:
		req.Resource = *r.Resource
	}
	switch {
	case it.Action != nil:
		a := *it.Action
		req.Action = &a
	case r.Action != nil:
		a := *r.Action
		req.Action = &a
	}
	ctx := r.Context
	if it.Context != nil {
		ctx = it.Context
	}
	if ctx != nil {
		req.Context = make(map[string]interface{}, len(ctx))
		for k, v := range ctx {
			req.Context[k] = v
		}
	}
	return req, nil
}
