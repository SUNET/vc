package trustping

import (
	"testing"

	"github.com/SUNET/vc/pkg/didcomm/message"
)

func TestNewPing(t *testing.T) {
	ping, err := NewPing(
		"did:example:alice",
		"did:example:bob",
		WithResponseRequested(true),
		WithComment("Hello!"),
	)
	if err != nil {
		t.Fatalf("NewPing() error = %v", err)
	}

	if ping.Type != TypePing {
		t.Errorf("Type = %v, want %v", ping.Type, TypePing)
	}

	if ping.From != "did:example:alice" {
		t.Errorf("From = %v, want did:example:alice", ping.From)
	}

	if len(ping.To) != 1 || ping.To[0] != "did:example:bob" {
		t.Errorf("To = %v, want [did:example:bob]", ping.To)
	}

	var body PingBody
	if err := ping.GetBody(&body); err != nil {
		t.Fatalf("GetBody() error = %v", err)
	}

	if !body.ResponseRequested {
		t.Error("ResponseRequested = false, want true")
	}

	if body.Comment != "Hello!" {
		t.Errorf("Comment = %v, want Hello!", body.Comment)
	}
}

func TestNewPing_NoResponse(t *testing.T) {
	ping, err := NewPing(
		"did:example:alice",
		"did:example:bob",
		WithResponseRequested(false),
	)
	if err != nil {
		t.Fatalf("NewPing() error = %v", err)
	}

	if ResponseRequested(ping) {
		t.Error("ResponseRequested() = true, want false")
	}
}

func TestNewPingResponse(t *testing.T) {
	ping, _ := NewPing("did:example:alice", "did:example:bob")

	response, err := NewPingResponse(ping, "Pong!")
	if err != nil {
		t.Fatalf("NewPingResponse() error = %v", err)
	}

	if response.Type != TypePingResponse {
		t.Errorf("Type = %v, want %v", response.Type, TypePingResponse)
	}

	// Response should be from bob to alice
	if response.From != "did:example:bob" {
		t.Errorf("From = %v, want did:example:bob", response.From)
	}

	if len(response.To) != 1 || response.To[0] != "did:example:alice" {
		t.Errorf("To = %v, want [did:example:alice]", response.To)
	}

	// Thread ID should match ping's thread ID
	if response.ThreadID() != ping.ThreadID() {
		t.Errorf("ThreadID = %v, want %v", response.ThreadID(), ping.ThreadID())
	}

	var body PingResponseBody
	if err := response.GetBody(&body); err != nil {
		t.Fatalf("GetBody() error = %v", err)
	}

	if body.Comment != "Pong!" {
		t.Errorf("Comment = %v, want Pong!", body.Comment)
	}
}

func TestNewPingResponse_WrongType(t *testing.T) {
	// Create a non-ping message
	msg := message.New(message.WithType("https://example.com/other"))

	_, err := NewPingResponse(msg, "")
	if err == nil {
		t.Error("expected error for non-ping message")
	}
}

func TestHandlePing(t *testing.T) {
	ping, _ := NewPing("did:example:alice", "did:example:bob")

	response, err := HandlePing(ping)
	if err != nil {
		t.Fatalf("HandlePing() error = %v", err)
	}

	if response == nil {
		t.Error("expected response, got nil")
	}

	if response.Type != TypePingResponse {
		t.Errorf("Type = %v, want %v", response.Type, TypePingResponse)
	}
}

func TestHandlePing_NoResponseRequested(t *testing.T) {
	ping, _ := NewPing("did:example:alice", "did:example:bob", WithResponseRequested(false))

	response, err := HandlePing(ping)
	if err != nil {
		t.Fatalf("HandlePing() error = %v", err)
	}

	if response != nil {
		t.Error("expected nil response when not requested")
	}
}

func TestIsPing(t *testing.T) {
	ping, _ := NewPing("did:example:alice", "did:example:bob")
	if !IsPing(ping) {
		t.Error("IsPing() = false for ping message")
	}

	other := message.New(message.WithType("https://example.com/other"))
	if IsPing(other) {
		t.Error("IsPing() = true for non-ping message")
	}
}

func TestIsPingResponse(t *testing.T) {
	ping, _ := NewPing("did:example:alice", "did:example:bob")
	response, _ := NewPingResponse(ping, "")

	if !IsPingResponse(response) {
		t.Error("IsPingResponse() = false for ping response")
	}

	if IsPingResponse(ping) {
		t.Error("IsPingResponse() = true for ping message")
	}
}
