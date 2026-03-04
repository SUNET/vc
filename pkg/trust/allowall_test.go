package trust

import (
	"context"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

func TestAllowAllEvaluator_Evaluate(t *testing.T) {
	eval := NewAllowAllEvaluator()

	tests := []struct {
		name    string
		req     *EvaluationRequest
		wantErr bool
	}{
		{
			name: "accepts JWK",
			req: &EvaluationRequest{
				EvaluationRequest: trustapi.EvaluationRequest{
					SubjectID: "https://issuer.example.com",
					KeyType:   KeyTypeJWK,
					Key:       map[string]any{"kty": "EC"},
				},
			},
			wantErr: false,
		},
		{
			name: "accepts X5C",
			req: &EvaluationRequest{
				EvaluationRequest: trustapi.EvaluationRequest{
					SubjectID: "https://issuer.example.com",
					KeyType:   KeyTypeX5C,
					Key:       []string{"base64cert"},
				},
			},
			wantErr: false,
		},
		{
			name:    "rejects nil request",
			req:     nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := eval.Evaluate(context.Background(), tt.req)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !decision.Trusted {
				t.Error("expected Trusted=true in allow-all mode")
			}

			if decision.TrustFramework != TrustFrameworkNone {
				t.Errorf("expected TrustFramework=%q, got %s", TrustFrameworkNone, decision.TrustFramework)
			}
		})
	}
}

func TestAllowAllEvaluator_SupportsKeyType(t *testing.T) {
	eval := NewAllowAllEvaluator()

	if !eval.SupportsKeyType(KeyTypeJWK) {
		t.Error("AllowAllEvaluator should support JWK")
	}

	if !eval.SupportsKeyType(KeyTypeX5C) {
		t.Error("AllowAllEvaluator should support X5C")
	}
}

func TestAllowAllEvaluator_ResolveKey(t *testing.T) {
	eval := NewAllowAllEvaluator()

	// Key resolution should not be supported in allow-all mode
	_, err := eval.ResolveKey(context.Background(), "did:key:z6...")
	if err == nil {
		t.Error("expected error for ResolveKey in allow-all mode")
	}
}
