// Package presentproof implements the DIDComm present-proof protocol 3.0.
// This protocol enables requesting and presenting verifiable credentials
// and presentations between DIDComm agents.
//
// Protocol URI: https://didcomm.org/present-proof/3.0
//
// Message flow:
//  1. Verifier sends request-presentation to Holder
//  2. Holder sends presentation to Verifier OR
//  3. Holder sends propose-presentation to negotiate what to present
//
// See: https://identity.foundation/didcomm-messaging/spec/
package presentproof

import (
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/didcomm/message"
)

const (
	// Protocol identifier
	ProtocolURI = "https://didcomm.org/present-proof/3.0"

	// Message types
	TypeProposePresentation = ProtocolURI + "/propose-presentation"
	TypeRequestPresentation = ProtocolURI + "/request-presentation"
	TypePresentation        = ProtocolURI + "/presentation"
	TypePresentationAck     = ProtocolURI + "/ack"
	TypePresentationProblem = ProtocolURI + "/problem-report"

	// Attachment formats
	FormatDIFPresentationExchange   = "dif/presentation-exchange/definitions@v2.0"
	FormatDIFPresentationSubmission = "dif/presentation-exchange/submission@v2.0"
	FormatW3CVC                     = "w3c/vc@v2.0"
	FormatW3CVP                     = "w3c/vp@v2.0"

	// MediaTypeJSON is the standard JSON media type for attachments.
	MediaTypeJSON = "application/json"
)

// ProposePresentation represents a proposal from holder to verifier
// about what credentials they could present.
type ProposePresentation struct {
	GoalCode       string       `json:"goal_code,omitempty"`
	Comment        string       `json:"comment,omitempty"`
	ProposalAttach []Attachment `json:"proposals~attach,omitempty"`
}

// RequestPresentation represents a request from verifier to holder
// for specific credentials or presentations.
type RequestPresentation struct {
	GoalCode      string       `json:"goal_code,omitempty"`
	Comment       string       `json:"comment,omitempty"`
	WillConfirm   bool         `json:"will_confirm,omitempty"`
	RequestAttach []Attachment `json:"request_presentations~attach"`
}

// Presentation represents a credential presentation from holder to verifier.
type Presentation struct {
	GoalCode           string       `json:"goal_code,omitempty"`
	Comment            string       `json:"comment,omitempty"`
	LastPresentation   bool         `json:"last_presentation,omitempty"`
	PresentationAttach []Attachment `json:"presentations~attach"`
}

// Attachment represents a DIDComm attachment carrying credential/presentation data.
type Attachment struct {
	ID        string         `json:"@id"`
	MediaType string         `json:"media_type,omitempty"`
	Format    string         `json:"format,omitempty"`
	Data      AttachmentData `json:"data"`
}

// AttachmentData holds the content of an attachment.
type AttachmentData struct {
	JSON   json.RawMessage `json:"json,omitempty"`
	Base64 string          `json:"base64,omitempty"`
	Links  []string        `json:"links,omitempty"`
	JWS    string          `json:"jws,omitempty"`
}

// RequestOption configures request creation.
type RequestOption func(*requestConfig)

type requestConfig struct {
	goalCode    string
	comment     string
	willConfirm bool
}

// WithGoalCode sets the goal code for the request.
func WithGoalCode(code string) RequestOption {
	return func(c *requestConfig) {
		c.goalCode = code
	}
}

// WithComment adds a human-readable comment.
func WithComment(comment string) RequestOption {
	return func(c *requestConfig) {
		c.comment = comment
	}
}

// WithConfirmation indicates the verifier will send an ack.
func WithConfirmation(confirm bool) RequestOption {
	return func(c *requestConfig) {
		c.willConfirm = confirm
	}
}

// NewRequestPresentation creates a new presentation request message.
// The presentationDef should be a DIF Presentation Definition (JSON).
func NewRequestPresentation(from, to string, presentationDef json.RawMessage, opts ...RequestOption) (*message.Message, error) {
	cfg := &requestConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	body := RequestPresentation{
		GoalCode:    cfg.goalCode,
		Comment:     cfg.comment,
		WillConfirm: cfg.willConfirm,
		RequestAttach: []Attachment{
			{
				ID:        "request-0",
				MediaType: MediaTypeJSON,
				Format:    FormatDIFPresentationExchange,
				Data: AttachmentData{
					JSON: presentationDef,
				},
			},
		},
	}

	msgOpts := []message.Option{
		message.WithType(TypeRequestPresentation),
		message.WithFrom(from),
		message.WithTo(to),
	}

	msg := message.New(msgOpts...)

	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set request body: %w", err)
	}

	return msg, nil
}

// NewPresentation creates a new presentation message in response to a request.
// The vp should be a W3C Verifiable Presentation (JSON).
func NewPresentation(request *message.Message, vp json.RawMessage, opts ...RequestOption) (*message.Message, error) {
	if request.Type != TypeRequestPresentation {
		return nil, fmt.Errorf("expected request-presentation message, got %s", request.Type)
	}

	cfg := &requestConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	body := Presentation{
		GoalCode:         cfg.goalCode,
		Comment:          cfg.comment,
		LastPresentation: true,
		PresentationAttach: []Attachment{
			{
				ID:        "presentation-0",
				MediaType: MediaTypeJSON,
				Format:    FormatW3CVP,
				Data: AttachmentData{
					JSON: vp,
				},
			},
		},
	}

	msgOpts := []message.Option{
		message.WithType(TypePresentation),
		message.WithFrom(request.To[0]),
		message.WithTo(request.From),
		message.WithThreadID(request.ID),
	}

	msg := message.New(msgOpts...)

	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set presentation body: %w", err)
	}

	return msg, nil
}

// NewProposePresentation creates a new presentation proposal message.
func NewProposePresentation(from, to string, proposal json.RawMessage, opts ...RequestOption) (*message.Message, error) {
	cfg := &requestConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	body := ProposePresentation{
		GoalCode: cfg.goalCode,
		Comment:  cfg.comment,
		ProposalAttach: []Attachment{
			{
				ID:        "proposal-0",
				MediaType: MediaTypeJSON,
				Format:    FormatDIFPresentationExchange,
				Data: AttachmentData{
					JSON: proposal,
				},
			},
		},
	}

	msgOpts := []message.Option{
		message.WithType(TypeProposePresentation),
		message.WithFrom(from),
		message.WithTo(to),
	}

	msg := message.New(msgOpts...)

	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set proposal body: %w", err)
	}

	return msg, nil
}

// ParseRequestPresentation parses the body of a request-presentation message.
func ParseRequestPresentation(msg *message.Message) (*RequestPresentation, error) {
	if msg.Type != TypeRequestPresentation {
		return nil, fmt.Errorf("expected request-presentation message, got %s", msg.Type)
	}

	var body RequestPresentation
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse request body: %w", err)
	}

	return &body, nil
}

// ParsePresentation parses the body of a presentation message.
func ParsePresentation(msg *message.Message) (*Presentation, error) {
	if msg.Type != TypePresentation {
		return nil, fmt.Errorf("expected presentation message, got %s", msg.Type)
	}

	var body Presentation
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse presentation body: %w", err)
	}

	return &body, nil
}

// GetPresentationDefinition extracts the first presentation definition from a request.
func (r *RequestPresentation) GetPresentationDefinition() (json.RawMessage, error) {
	for _, attach := range r.RequestAttach {
		if attach.Format == FormatDIFPresentationExchange {
			if attach.Data.JSON != nil {
				return attach.Data.JSON, nil
			}
		}
	}
	return nil, fmt.Errorf("no presentation definition found in request")
}

// GetVerifiablePresentation extracts the first verifiable presentation.
func (p *Presentation) GetVerifiablePresentation() (json.RawMessage, error) {
	for _, attach := range p.PresentationAttach {
		if attach.Data.JSON != nil {
			return attach.Data.JSON, nil
		}
	}
	return nil, fmt.Errorf("no verifiable presentation found in message")
}
