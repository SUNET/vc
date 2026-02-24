//go:build didcomm && vc20

package oob

import (
	"strings"
	"testing"

	"vc/pkg/didcomm"
	"vc/pkg/didcomm/message"
)

func TestNewInvitation(t *testing.T) {
	inv, err := NewInvitation(
		"did:example:alice",
		WithGoalCode("connect"),
		WithGoal("Establish a secure connection"),
		WithAccept(didcomm.MediaTypeEncrypted),
	)
	if err != nil {
		t.Fatalf("NewInvitation() error = %v", err)
	}

	if inv.Type != TypeInvitation {
		t.Errorf("Type = %v, want %v", inv.Type, TypeInvitation)
	}

	if inv.From != "did:example:alice" {
		t.Errorf("From = %v, want did:example:alice", inv.From)
	}

	body, err := GetInvitationBody(inv)
	if err != nil {
		t.Fatalf("GetInvitationBody() error = %v", err)
	}

	if body.GoalCode != "connect" {
		t.Errorf("GoalCode = %v, want connect", body.GoalCode)
	}

	if body.Goal != "Establish a secure connection" {
		t.Errorf("Goal = %v, want 'Establish a secure connection'", body.Goal)
	}

	if len(body.Accept) != 1 || body.Accept[0] != didcomm.MediaTypeEncrypted {
		t.Errorf("Accept = %v, want [%s]", body.Accept, didcomm.MediaTypeEncrypted)
	}
}

func TestNewInvitation_Defaults(t *testing.T) {
	inv, err := NewInvitation("did:example:alice")
	if err != nil {
		t.Fatalf("NewInvitation() error = %v", err)
	}

	body, err := GetInvitationBody(inv)
	if err != nil {
		t.Fatalf("GetInvitationBody() error = %v", err)
	}

	// Should have default accept list
	if len(body.Accept) != 3 {
		t.Errorf("Accept = %v, want 3 default media types", body.Accept)
	}
}

func TestEncodeDecodeAsURL(t *testing.T) {
	inv, _ := NewInvitation(
		"did:example:alice",
		WithGoal("Connect"),
	)

	// Encode
	encoded, err := EncodeAsURL(inv, "https://example.com/invite")
	if err != nil {
		t.Fatalf("EncodeAsURL() error = %v", err)
	}

	if !strings.Contains(encoded, "_oob=") {
		t.Error("encoded URL should contain _oob parameter")
	}

	// Decode
	decoded, err := DecodeFromURL(encoded)
	if err != nil {
		t.Fatalf("DecodeFromURL() error = %v", err)
	}

	if decoded.ID != inv.ID {
		t.Errorf("decoded ID = %v, want %v", decoded.ID, inv.ID)
	}

	if decoded.From != inv.From {
		t.Errorf("decoded From = %v, want %v", decoded.From, inv.From)
	}
}

func TestEncodeAsURL_NonInvitation(t *testing.T) {
	msg := message.New(message.WithType("https://example.com/other"))

	_, err := EncodeAsURL(msg, "https://example.com")
	if err == nil {
		t.Error("expected error for non-invitation message")
	}
}

func TestDecodeFromURL_MissingParam(t *testing.T) {
	_, err := DecodeFromURL("https://example.com/invite")
	if err == nil {
		t.Error("expected error for URL without _oob parameter")
	}
}

func TestEncodeDecodeAsJSON(t *testing.T) {
	inv, _ := NewInvitation(
		"did:example:alice",
		WithGoalCode("issue-vc"),
	)

	// Encode
	jsonStr, err := EncodeAsJSON(inv)
	if err != nil {
		t.Fatalf("EncodeAsJSON() error = %v", err)
	}

	if !strings.Contains(jsonStr, "issue-vc") {
		t.Error("JSON should contain goal_code")
	}

	// Decode
	decoded, err := DecodeFromJSON([]byte(jsonStr))
	if err != nil {
		t.Fatalf("DecodeFromJSON() error = %v", err)
	}

	if decoded.ID != inv.ID {
		t.Errorf("decoded ID = %v, want %v", decoded.ID, inv.ID)
	}
}

func TestDecodeFromJSON_WrongType(t *testing.T) {
	jsonStr := `{"id":"123","type":"https://example.com/other"}`

	_, err := DecodeFromJSON([]byte(jsonStr))
	if err == nil {
		t.Error("expected error for non-invitation JSON")
	}
}

func TestIsInvitation(t *testing.T) {
	inv, _ := NewInvitation("did:example:alice")
	if !IsInvitation(inv) {
		t.Error("IsInvitation() = false for invitation")
	}

	other := message.New(message.WithType("https://example.com/other"))
	if IsInvitation(other) {
		t.Error("IsInvitation() = true for non-invitation")
	}
}

func TestWithHandshakeProtocols(t *testing.T) {
	inv, err := NewInvitation(
		"did:example:alice",
		WithHandshakeProtocols(
			"https://didcomm.org/didexchange/2.0",
			"https://didcomm.org/connections/1.0",
		),
	)
	if err != nil {
		t.Fatalf("NewInvitation() error = %v", err)
	}

	body, _ := GetInvitationBody(inv)
	if len(body.HandshakeProtocols) != 2 {
		t.Errorf("HandshakeProtocols = %v, want 2 protocols", body.HandshakeProtocols)
	}
}
