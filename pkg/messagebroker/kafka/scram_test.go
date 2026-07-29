package kafka

import (
	"testing"

	"github.com/xdg-go/scram"
)

func TestHashGenerators(t *testing.T) {
	tests := []struct {
		name       string
		gen        scram.HashGeneratorFcn
		wantDigest int
	}{
		{name: "SHA256", gen: SHA256, wantDigest: 32},
		{name: "SHA512", gen: SHA512, wantDigest: 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.gen()
			if h == nil {
				t.Fatal("hash generator returned nil")
			}
			h.Write([]byte("test"))
			if got := len(h.Sum(nil)); got != tt.wantDigest {
				t.Fatalf("digest length = %d, want %d", got, tt.wantDigest)
			}
		})
	}
}

func TestXDGSCRAMClient_Begin(t *testing.T) {
	tests := []struct {
		name    string
		hashFcn scram.HashGeneratorFcn
		user    string
		pass    string
		authzID string
	}{
		{name: "SHA256", hashFcn: SHA256, user: "user", pass: "password", authzID: ""},
		{name: "SHA512", hashFcn: SHA512, user: "user", pass: "password", authzID: ""},
		{name: "SHA512_with_authzID", hashFcn: SHA512, user: "user", pass: "password", authzID: "authz-user"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &XDGSCRAMClient{HashGeneratorFcn: tt.hashFcn}
			if err := client.Begin(tt.user, tt.pass, tt.authzID); err != nil {
				t.Fatalf("Begin() error = %v", err)
			}
			if client.ClientConversation == nil {
				t.Fatal("Begin() did not initialize ClientConversation")
			}
		})
	}
}

func TestXDGSCRAMClient_Step(t *testing.T) {
	tests := []struct {
		name    string
		hashFcn scram.HashGeneratorFcn
	}{
		{name: "SHA256", hashFcn: SHA256},
		{name: "SHA512", hashFcn: SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &XDGSCRAMClient{HashGeneratorFcn: tt.hashFcn}
			if err := client.Begin("user", "password", ""); err != nil {
				t.Fatalf("Begin() error = %v", err)
			}

			resp, err := client.Step("")
			if err != nil {
				t.Fatalf("Step() error = %v", err)
			}
			if resp == "" {
				t.Fatal("Step() returned empty client-first message")
			}
		})
	}
}

func TestXDGSCRAMClient_Done(t *testing.T) {
	tests := []struct {
		name    string
		hashFcn scram.HashGeneratorFcn
	}{
		{name: "SHA256", hashFcn: SHA256},
		{name: "SHA512", hashFcn: SHA512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &XDGSCRAMClient{HashGeneratorFcn: tt.hashFcn}
			if err := client.Begin("user", "password", ""); err != nil {
				t.Fatalf("Begin() error = %v", err)
			}
			if client.Done() {
				t.Fatal("Done() = true immediately after Begin(), want false")
			}
		})
	}
}
