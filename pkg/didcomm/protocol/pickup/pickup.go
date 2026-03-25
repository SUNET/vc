// Package pickup implements the DIDComm Pickup Protocol 2.0.
//
// This protocol enables retrieving messages from a mediator when the recipient
// is offline or uses asynchronous message delivery.
//
// Protocol URI: https://didcomm.org/messagepickup/2.0/
//
// See: https://identity.foundation/didcomm-messaging/spec/#pickup-protocol-20
package pickup

import (
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/didcomm/message"
)

const (
	ProtocolURI            = "https://didcomm.org/messagepickup/2.0"
	TypeStatusRequest      = ProtocolURI + "/status-request"
	TypeStatus             = ProtocolURI + "/status"
	TypeDeliveryRequest    = ProtocolURI + "/delivery-request"
	TypeDelivery           = ProtocolURI + "/delivery"
	TypeMessagesReceived   = ProtocolURI + "/messages-received"
	TypeLiveDeliveryChange = ProtocolURI + "/live-delivery-change"
)

// StatusRequest requests the current status of available messages.
type StatusRequest struct {
	RecipientKey string `json:"recipient_key,omitempty"`
}

// Status contains information about available messages at the mediator.
type Status struct {
	RecipientKey         string `json:"recipient_key,omitempty"`
	MessageCount         int    `json:"message_count"`
	LongestWaitedSeconds int64  `json:"longest_waited_seconds,omitempty"`
	NewestReceivedTime   string `json:"newest_received_time,omitempty"`
	TotalBytes           int64  `json:"total_bytes,omitempty"`
	LiveDelivery         bool   `json:"live_delivery,omitempty"`
}

// DeliveryRequest requests delivery of messages.
type DeliveryRequest struct {
	Limit        int    `json:"limit,omitempty"`
	RecipientKey string `json:"recipient_key,omitempty"`
}

// Delivery contains messages being delivered.
type Delivery struct {
	RecipientKey string              `json:"recipient_key,omitempty"`
	Attachments  []MessageAttachment `json:"~attach"`
}

// MessageAttachment contains a message being delivered.
type MessageAttachment struct {
	ID   string         `json:"@id"`
	Data AttachmentData `json:"data"`
}

// AttachmentData holds the message content.
type AttachmentData struct {
	Base64 string          `json:"base64,omitempty"`
	JSON   json.RawMessage `json:"json,omitempty"`
}

// MessagesReceived acknowledges receipt of messages.
type MessagesReceived struct {
	MessageIDList []string `json:"message_id_list"`
}

// LiveDeliveryChange requests a change in live delivery mode.
type LiveDeliveryChange struct {
	LiveDelivery bool `json:"live_delivery"`
}

// NewStatusRequest creates a status request message.
func NewStatusRequest(from, to string, recipientKey string) (*message.Message, error) {
	body := StatusRequest{RecipientKey: recipientKey}
	msgOpts := []message.Option{
		message.WithType(TypeStatusRequest),
		message.WithFrom(from),
		message.WithTo(to),
	}
	msg := message.New(msgOpts...)
	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set status request body: %w", err)
	}
	return msg, nil
}

// NewStatus creates a status response message.
func NewStatus(request *message.Message, status *Status) (*message.Message, error) {
	if request.Type != TypeStatusRequest {
		return nil, fmt.Errorf("expected status-request message, got %s", request.Type)
	}
	msgOpts := []message.Option{
		message.WithType(TypeStatus),
		message.WithFrom(request.To[0]),
		message.WithTo(request.From),
		message.WithThreadID(request.ID),
	}
	msg := message.New(msgOpts...)
	if err := msg.SetBody(status); err != nil {
		return nil, fmt.Errorf("failed to set status body: %w", err)
	}
	return msg, nil
}

// NewDeliveryRequest creates a message delivery request.
func NewDeliveryRequest(from, to string, limit int, recipientKey string) (*message.Message, error) {
	body := DeliveryRequest{Limit: limit, RecipientKey: recipientKey}
	msgOpts := []message.Option{
		message.WithType(TypeDeliveryRequest),
		message.WithFrom(from),
		message.WithTo(to),
	}
	msg := message.New(msgOpts...)
	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set delivery request body: %w", err)
	}
	return msg, nil
}

// NewDelivery creates a delivery message with attached messages.
func NewDelivery(request *message.Message, attachments []MessageAttachment) (*message.Message, error) {
	if request.Type != TypeDeliveryRequest {
		return nil, fmt.Errorf("expected delivery-request message, got %s", request.Type)
	}
	body := Delivery{Attachments: attachments}
	msgOpts := []message.Option{
		message.WithType(TypeDelivery),
		message.WithFrom(request.To[0]),
		message.WithTo(request.From),
		message.WithThreadID(request.ID),
	}
	msg := message.New(msgOpts...)
	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set delivery body: %w", err)
	}
	return msg, nil
}

// NewMessagesReceived creates an acknowledgment of received messages.
func NewMessagesReceived(from, to string, messageIDs []string) (*message.Message, error) {
	body := MessagesReceived{MessageIDList: messageIDs}
	msgOpts := []message.Option{
		message.WithType(TypeMessagesReceived),
		message.WithFrom(from),
		message.WithTo(to),
	}
	msg := message.New(msgOpts...)
	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set messages-received body: %w", err)
	}
	return msg, nil
}

// NewLiveDeliveryChange creates a live delivery mode change request.
func NewLiveDeliveryChange(from, to string, enable bool) (*message.Message, error) {
	body := LiveDeliveryChange{LiveDelivery: enable}
	msgOpts := []message.Option{
		message.WithType(TypeLiveDeliveryChange),
		message.WithFrom(from),
		message.WithTo(to),
	}
	msg := message.New(msgOpts...)
	if err := msg.SetBody(body); err != nil {
		return nil, fmt.Errorf("failed to set live-delivery-change body: %w", err)
	}
	return msg, nil
}

// ParseStatusRequest parses a status request message.
func ParseStatusRequest(msg *message.Message) (*StatusRequest, error) {
	if msg.Type != TypeStatusRequest {
		return nil, fmt.Errorf("expected status-request message, got %s", msg.Type)
	}
	var body StatusRequest
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse status request body: %w", err)
	}
	return &body, nil
}

// ParseStatus parses a status response message.
func ParseStatus(msg *message.Message) (*Status, error) {
	if msg.Type != TypeStatus {
		return nil, fmt.Errorf("expected status message, got %s", msg.Type)
	}
	var body Status
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse status body: %w", err)
	}
	return &body, nil
}

// ParseDeliveryRequest parses a delivery request message.
func ParseDeliveryRequest(msg *message.Message) (*DeliveryRequest, error) {
	if msg.Type != TypeDeliveryRequest {
		return nil, fmt.Errorf("expected delivery-request message, got %s", msg.Type)
	}
	var body DeliveryRequest
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse delivery request body: %w", err)
	}
	return &body, nil
}

// ParseDelivery parses a delivery message.
func ParseDelivery(msg *message.Message) (*Delivery, error) {
	if msg.Type != TypeDelivery {
		return nil, fmt.Errorf("expected delivery message, got %s", msg.Type)
	}
	var body Delivery
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse delivery body: %w", err)
	}
	return &body, nil
}

// ParseMessagesReceived parses a messages-received acknowledgment.
func ParseMessagesReceived(msg *message.Message) (*MessagesReceived, error) {
	if msg.Type != TypeMessagesReceived {
		return nil, fmt.Errorf("expected messages-received message, got %s", msg.Type)
	}
	var body MessagesReceived
	if err := msg.GetBody(&body); err != nil {
		return nil, fmt.Errorf("failed to parse messages-received body: %w", err)
	}
	return &body, nil
}
