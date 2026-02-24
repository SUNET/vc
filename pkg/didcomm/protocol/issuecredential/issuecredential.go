//go:build didcomm && vc20

// Package issuecredential implements the DIDComm Issue Credential protocol 3.0.
//
// This protocol enables issuing verifiable credentials from an issuer to a holder
// over DIDComm messaging.
//
// Protocol URI: https://didcomm.org/issue-credential/3.0
//
// Message flow:
//  1. Holder sends propose-credential (optional)
//  2. Issuer sends offer-credential with preview
//  3. Holder sends request-credential to accept
//  4. Issuer sends issue-credential with the credential
//  5. Holder sends ack (optional)
//
// See: https://github.com/hyperledger/aries-rfcs/blob/main/features/0453-issue-credential-v2/README.md
package issuecredential

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"vc/pkg/didcomm/message"
)

const (
	// Protocol identifier
	ProtocolURI = "https://didcomm.org/issue-credential/3.0"

	// Message types
	TypeProposeCredential = ProtocolURI + "/propose-credential"
	TypeOfferCredential   = ProtocolURI + "/offer-credential"
	TypeRequestCredential = ProtocolURI + "/request-credential"
	TypeIssueCredential   = ProtocolURI + "/issue-credential"
	TypeCredentialAck     = ProtocolURI + "/ack"
	TypeCredentialProblem = ProtocolURI + "/problem-report"

	// Attachment formats
	FormatLDProofVCDetail    = "aries/ld-proof-vc-detail@v2.0"
	FormatLDProofVC          = "aries/ld-proof-vc@v2.0"
	FormatCredentialManifest = "dif/credential-manifest@v1.0"
	FormatJWTOffer           = "jwt/credential-offer@v1.0"
	FormatJWTVC              = "jwt/vc@v1.0"
	FormatSDJWTVC            = "dc+sd-jwt"

	// Goal codes
	GoalCodeIssueVC = "aries.vc.issue"

	// Preview type
	PreviewType = "https://didcomm.org/issue-credential/3.0/credential-preview"
)

// ProposeCredential is sent by holder to initiate credential issuance.
type ProposeCredential struct {
	GoalCode          string       `json:"goal_code,omitempty"`
	Comment           string       `json:"comment,omitempty"`
	CredentialPreview *Preview     `json:"credential_preview,omitempty"`
	FiltersAttach     []Attachment `json:"filters~attach,omitempty"`
}

// OfferCredential is sent by issuer with credential details.
type OfferCredential struct {
	GoalCode          string       `json:"goal_code,omitempty"`
	Comment           string       `json:"comment,omitempty"`
	ReplacementID     string       `json:"replacement_id,omitempty"`
	CredentialPreview *Preview     `json:"credential_preview,omitempty"`
	OffersAttach      []Attachment `json:"offers~attach"`
}

// RequestCredential is sent by holder to accept an offer.
type RequestCredential struct {
	GoalCode       string       `json:"goal_code,omitempty"`
	Comment        string       `json:"comment,omitempty"`
	RequestsAttach []Attachment `json:"requests~attach"`
}

// IssueCredential delivers the credential to holder.
type IssueCredential struct {
	GoalCode          string       `json:"goal_code,omitempty"`
	Comment           string       `json:"comment,omitempty"`
	ReplacementID     string       `json:"replacement_id,omitempty"`
	CredentialsAttach []Attachment `json:"credentials~attach"`
}

// Preview describes the credential before issuance.
type Preview struct {
	Type       string             `json:"@type"`
	Attributes []PreviewAttribute `json:"attributes"`
}

// PreviewAttribute is a claim in the credential preview.
type PreviewAttribute struct {
	Name     string `json:"name"`
	MimeType string `json:"mime-type,omitempty"`
	Value    string `json:"value"`
}

// Attachment carries credential data.
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

// LDProofVCDetail is the attachment format for W3C VC Data Integrity offers/requests.
type LDProofVCDetail struct {
	Credential json.RawMessage `json:"credential"`
	Options    *LDProofOptions `json:"options,omitempty"`
}

// LDProofOptions specifies signing options for LD Proof credentials.
type LDProofOptions struct {
	ProofType  string `json:"proofType,omitempty"`
	ProofPurpose string `json:"proofPurpose,omitempty"`
	Created    string `json:"created,omitempty"`
	Challenge  string `json:"challenge,omitempty"`
	Domain     string `json:"domain,omitempty"`
}

// OfferOption configures offer creation.
type OfferOption func(*offerConfig)

type offerConfig struct {
	goalCode      string
	comment       string
	replacementID string
}

// WithOfferGoalCode sets the goal code for the offer.
func WithOfferGoalCode(code string) OfferOption {
	return func(c *offerConfig) {
		c.goalCode = code
	}
}

// WithOfferComment adds a human-readable comment to the offer.
func WithOfferComment(comment string) OfferOption {
	return func(c *offerConfig) {
		c.comment = comment
	}
}

// WithReplacementID indicates the credential being replaced.
func WithReplacementID(id string) OfferOption {
	return func(c *offerConfig) {
		c.replacementID = id
	}
}

// RequestOption configures request creation.
type RequestOption func(*requestConfig)

type requestConfig struct {
	goalCode string
	comment  string
}

// WithRequestGoalCode sets the goal code for the request.
func WithRequestGoalCode(code string) RequestOption {
	return func(c *requestConfig) {
		c.goalCode = code
	}
}

// WithRequestComment adds a human-readable comment to the request.
func WithRequestComment(comment string) RequestOption {
	return func(c *requestConfig) {
		c.comment = comment
	}
}

// IssueOption configures issue message creation.
type IssueOption func(*issueConfig)

type issueConfig struct {
	goalCode      string
	comment       string
	replacementID string
}

// WithIssueGoalCode sets the goal code.
func WithIssueGoalCode(code string) IssueOption {
	return func(c *issueConfig) {
		c.goalCode = code
	}
}

// WithIssueComment adds a comment.
func WithIssueComment(comment string) IssueOption {
	return func(c *issueConfig) {
		c.comment = comment
	}
}

// WithIssueReplacementID indicates the credential being replaced.
func WithIssueReplacementID(id string) IssueOption {
	return func(c *issueConfig) {
		c.replacementID = id
	}
}

// ProposeOption configures proposal creation.
type ProposeOption func(*proposeConfig)

type proposeConfig struct {
	goalCode string
	comment  string
}

// WithProposeGoalCode sets the goal code.
func WithProposeGoalCode(code string) ProposeOption {
	return func(c *proposeConfig) {
		c.goalCode = code
	}
}

// WithProposeComment adds a comment.
func WithProposeComment(comment string) ProposeOption {
	return func(c *proposeConfig) {
		c.comment = comment
	}
}

// NewPreview creates a credential preview with the given attributes.
func NewPreview(attributes map[string]string) *Preview {
	preview := &Preview{
		Type:       PreviewType,
		Attributes: make([]PreviewAttribute, 0, len(attributes)),
	}
	for name, value := range attributes {
		preview.Attributes = append(preview.Attributes, PreviewAttribute{
			Name:  name,
			Value: value,
		})
	}
	return preview
}

// NewOfferCredential creates a new credential offer message.
// The credentialDetail should be a credential template or manifest (JSON).
func NewOfferCredential(from, to string, preview *Preview, credentialDetail json.RawMessage, format string, opts ...OfferOption) (*message.Message, error) {
	cfg := &offerConfig{
		goalCode: GoalCodeIssueVC,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	attachID := uuid.New().String()
	body := OfferCredential{
		GoalCode:          cfg.goalCode,
		Comment:           cfg.comment,
		ReplacementID:     cfg.replacementID,
		CredentialPreview: preview,
		OffersAttach: []Attachment{
			{
				ID:     attachID,
				Format: format,
				Data: AttachmentData{
					JSON: credentialDetail,
				},
			},
		},
	}

	msgOpts := []message.Option{
		message.WithType(TypeOfferCredential),
		message.WithFrom(from),
		message.WithTo(to),
	}

	msg := message.New(msgOpts...)
	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set offer body: %w", err)
	}

	return msg, nil
}

// NewRequestCredential creates a request message accepting an offer.
// The holderBinding can contain key binding information for the credential.
func NewRequestCredential(offer *message.Message, holderBinding json.RawMessage, opts ...RequestOption) (*message.Message, error) {
	if offer.Type != TypeOfferCredential {
		return nil, fmt.Errorf("expected offer-credential message, got %s", offer.Type)
	}

	cfg := &requestConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Parse offer to get attachment format
	var offerBody OfferCredential
	if err := offer.GetBody(&offerBody); err != nil {
		return nil, fmt.Errorf("failed to parse offer body: %w", err)
	}

	// Build request attachments based on offer
	var requestAttach []Attachment
	for _, offerAttach := range offerBody.OffersAttach {
		attachData := AttachmentData{}
		if holderBinding != nil {
			attachData.JSON = holderBinding
		} else {
			// Echo the offer attachment for simple acceptance
			attachData = offerAttach.Data
		}
		requestAttach = append(requestAttach, Attachment{
			ID:     uuid.New().String(),
			Format: offerAttach.Format,
			Data:   attachData,
		})
	}

	body := RequestCredential{
		GoalCode:       cfg.goalCode,
		Comment:        cfg.comment,
		RequestsAttach: requestAttach,
	}

	msgOpts := []message.Option{
		message.WithType(TypeRequestCredential),
		message.WithFrom(offer.To[0]),
		message.WithTo(offer.From),
		message.WithThreadID(offer.ID),
	}

	msg := message.New(msgOpts...)
	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set request body: %w", err)
	}

	return msg, nil
}

// NewIssueCredential creates the credential delivery message.
func NewIssueCredential(request *message.Message, credential json.RawMessage, format string, opts ...IssueOption) (*message.Message, error) {
	if request.Type != TypeRequestCredential {
		return nil, fmt.Errorf("expected request-credential message, got %s", request.Type)
	}

	cfg := &issueConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	body := IssueCredential{
		GoalCode:      cfg.goalCode,
		Comment:       cfg.comment,
		ReplacementID: cfg.replacementID,
		CredentialsAttach: []Attachment{
			{
				ID:     uuid.New().String(),
				Format: format,
				Data: AttachmentData{
					JSON: credential,
				},
			},
		},
	}

	// Get thread ID from request
	threadID := request.ThreadID()

	msgOpts := []message.Option{
		message.WithType(TypeIssueCredential),
		message.WithFrom(request.To[0]),
		message.WithTo(request.From),
		message.WithThreadID(threadID),
	}

	msg := message.New(msgOpts...)
	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set issue body: %w", err)
	}

	return msg, nil
}

// NewProposeCredential creates a proposal from holder to issuer.
func NewProposeCredential(from, to string, preview *Preview, filter json.RawMessage, opts ...ProposeOption) (*message.Message, error) {
	cfg := &proposeConfig{
		goalCode: GoalCodeIssueVC,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	body := ProposeCredential{
		GoalCode:          cfg.goalCode,
		Comment:           cfg.comment,
		CredentialPreview: preview,
	}

	if filter != nil {
		body.FiltersAttach = []Attachment{
			{
				ID:     uuid.New().String(),
				Format: FormatCredentialManifest,
				Data: AttachmentData{
					JSON: filter,
				},
			},
		}
	}

	msgOpts := []message.Option{
		message.WithType(TypeProposeCredential),
		message.WithFrom(from),
		message.WithTo(to),
	}

	msg := message.New(msgOpts...)
	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set propose body: %w", err)
	}

	return msg, nil
}

// NewCredentialAck creates an acknowledgment for a received credential.
func NewCredentialAck(issue *message.Message) (*message.Message, error) {
	if issue.Type != TypeIssueCredential {
		return nil, fmt.Errorf("expected issue-credential message, got %s", issue.Type)
	}

	// Get thread ID
	threadID := issue.ThreadID()

	msgOpts := []message.Option{
		message.WithType(TypeCredentialAck),
		message.WithFrom(issue.To[0]),
		message.WithTo(issue.From),
		message.WithThreadID(threadID),
	}

	msg := message.New(msgOpts...)
	// Ack has empty body
	if err := msg.SetBody(map[string]string{"status": "OK"}); err != nil {
		return nil, fmt.Errorf("failed to set ack body: %w", err)
	}

	return msg, nil
}

// ParseOfferCredential parses an offer message.
func ParseOfferCredential(msg *message.Message) (*OfferCredential, error) {
	if msg.Type != TypeOfferCredential {
		return nil, fmt.Errorf("expected offer-credential message, got %s", msg.Type)
	}
	var body OfferCredential
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse offer body: %w", err)
	}
	return &body, nil
}

// ParseRequestCredential parses a request message.
func ParseRequestCredential(msg *message.Message) (*RequestCredential, error) {
	if msg.Type != TypeRequestCredential {
		return nil, fmt.Errorf("expected request-credential message, got %s", msg.Type)
	}
	var body RequestCredential
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse request body: %w", err)
	}
	return &body, nil
}

// ParseIssueCredential parses an issue message.
func ParseIssueCredential(msg *message.Message) (*IssueCredential, error) {
	if msg.Type != TypeIssueCredential {
		return nil, fmt.Errorf("expected issue-credential message, got %s", msg.Type)
	}
	var body IssueCredential
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse issue body: %w", err)
	}
	return &body, nil
}

// ParseProposeCredential parses a propose message.
func ParseProposeCredential(msg *message.Message) (*ProposeCredential, error) {
	if msg.Type != TypeProposeCredential {
		return nil, fmt.Errorf("expected propose-credential message, got %s", msg.Type)
	}
	var body ProposeCredential
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse propose body: %w", err)
	}
	return &body, nil
}

// GetCredential extracts the credential from an issue message.
func (i *IssueCredential) GetCredential() (json.RawMessage, string, error) {
	if len(i.CredentialsAttach) == 0 {
		return nil, "", fmt.Errorf("no credential attachment found")
	}
	attach := i.CredentialsAttach[0]
	if attach.Data.JSON != nil {
		return attach.Data.JSON, attach.Format, nil
	}
	if attach.Data.Base64 != "" {
		// TODO: decode base64
		return nil, attach.Format, fmt.Errorf("base64 credential not yet supported")
	}
	return nil, "", fmt.Errorf("no credential data in attachment")
}

// GetOfferDetail extracts the credential detail from an offer.
func (o *OfferCredential) GetOfferDetail() (json.RawMessage, string, error) {
	if len(o.OffersAttach) == 0 {
		return nil, "", fmt.Errorf("no offer attachment found")
	}
	attach := o.OffersAttach[0]
	if attach.Data.JSON != nil {
		return attach.Data.JSON, attach.Format, nil
	}
	return nil, "", fmt.Errorf("no offer data in attachment")
}
