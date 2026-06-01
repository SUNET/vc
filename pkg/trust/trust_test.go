package trust

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// createTestCertChain creates a test certificate chain (leaf + root).
func createTestCertChain(t *testing.T) ([]*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
			Country:      []string{"SE"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root certificate: %v", err)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("failed to parse root certificate: %v", err)
	}

	// Generate leaf certificate
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "https://issuer.example.com",
			Organization: []string{"Test Issuer"},
			Country:      []string{"SE"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	return []*x509.Certificate{leafCert, rootCert}, rootCert, leafKey
}

func TestLocalTrustEvaluator_X5C(t *testing.T) {
	chain, rootCert, _ := createTestCertChain(t)

	eval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	})

	ctx := t.Context()

	t.Run("valid chain is trusted", func(t *testing.T) {
		decision, err := eval.Evaluate(ctx, &EvaluationRequest{
			EvaluationRequest: trustapi.EvaluationRequest{
				SubjectID: "https://issuer.example.com",
				KeyType:   KeyTypeX5C,
				Key:       chain,
				Role:      RoleIssuer,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !decision.Trusted {
			t.Errorf("expected trusted decision, got: %s", decision.Reason)
		}
	})

	t.Run("untrusted root is rejected", func(t *testing.T) {
		untrustedChain, _, _ := createTestCertChain(t) // Different root

		decision, err := eval.Evaluate(ctx, &EvaluationRequest{
			EvaluationRequest: trustapi.EvaluationRequest{
				SubjectID: "https://issuer.example.com",
				KeyType:   KeyTypeX5C,
				Key:       untrustedChain,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Trusted {
			t.Error("expected untrusted decision for unknown root")
		}
	})

	t.Run("subject mismatch is rejected", func(t *testing.T) {
		decision, err := eval.Evaluate(ctx, &EvaluationRequest{
			EvaluationRequest: trustapi.EvaluationRequest{
				SubjectID: "https://different.example.com", // Doesn't match cert CN
				KeyType:   KeyTypeX5C,
				Key:       chain,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Trusted {
			t.Error("expected untrusted decision for subject mismatch")
		}
	})
}

func TestLocalTrustEvaluator_ExpiredCert(t *testing.T) {
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Expired Root"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Expired Leaf"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour), // Expired
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	eval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	})

	decision, err := eval.Evaluate(t.Context(), &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			KeyType: KeyTypeX5C,
			Key:     []*x509.Certificate{leafCert, rootCert},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Trusted {
		t.Error("expected untrusted decision for expired certificate")
	}
	if decision.Reason == "" {
		t.Error("expected reason for untrusted decision")
	}
}

func TestLocalTrustEvaluator_RoleRestriction(t *testing.T) {
	chain, rootCert, _ := createTestCertChain(t)

	eval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
		AllowedRoles: []string{string(RoleIssuer)},
	})

	ctx := t.Context()

	t.Run("allowed role is accepted", func(t *testing.T) {
		decision, err := eval.Evaluate(ctx, &EvaluationRequest{
			EvaluationRequest: trustapi.EvaluationRequest{
				SubjectID: "https://issuer.example.com",
				KeyType:   KeyTypeX5C,
				Key:       chain,
				Role:      RoleIssuer,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !decision.Trusted {
			t.Errorf("expected trusted for allowed role, got: %s", decision.Reason)
		}
	})

	t.Run("disallowed role is rejected", func(t *testing.T) {
		decision, err := eval.Evaluate(ctx, &EvaluationRequest{
			EvaluationRequest: trustapi.EvaluationRequest{
				SubjectID: "https://issuer.example.com",
				KeyType:   KeyTypeX5C,
				Key:       chain,
				Role:      RoleVerifier, // Not in allowed roles
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Trusted {
			t.Error("expected untrusted for disallowed role")
		}
	})
}

func TestCompositeEvaluator_FirstSuccess(t *testing.T) {
	chain, rootCert, _ := createTestCertChain(t)

	// Create evaluators: first rejects, second accepts
	rejectingEval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{}, // Empty, will reject
	})
	acceptingEval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	})

	composite := NewCompositeEvaluator(StrategyFirstSuccess, rejectingEval, acceptingEval)

	decision, err := composite.Evaluate(t.Context(), &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeX5C,
			Key:       chain,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Trusted {
		t.Errorf("expected trusted (first success), got: %s", decision.Reason)
	}
}

func TestCompositeEvaluator_Fallback(t *testing.T) {
	chain, rootCert, _ := createTestCertChain(t)

	acceptingEval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	})

	composite := NewCompositeEvaluator(StrategyFallback, acceptingEval)

	decision, err := composite.Evaluate(t.Context(), &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeX5C,
			Key:       chain,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Trusted {
		t.Errorf("expected trusted (fallback), got: %s", decision.Reason)
	}
}

func TestX5CCertChain(t *testing.T) {
	chain, _, _ := createTestCertChain(t)
	certChain := X5CCertChain(chain)

	t.Run("GetLeafCert", func(t *testing.T) {
		leaf := certChain.GetLeafCert()
		if leaf == nil {
			t.Fatal("expected leaf cert")
		}
		if leaf.Subject.CommonName != "https://issuer.example.com" {
			t.Errorf("unexpected leaf CN: %s", leaf.Subject.CommonName)
		}
	})

	t.Run("GetRootCert", func(t *testing.T) {
		root := certChain.GetRootCert()
		if root == nil {
			t.Fatal("expected root cert")
		}
		if root.Subject.CommonName != "Test Root CA" {
			t.Errorf("unexpected root CN: %s", root.Subject.CommonName)
		}
	})

	t.Run("GetSubjectID", func(t *testing.T) {
		subjectID := certChain.GetSubjectID()
		if subjectID != "https://issuer.example.com" {
			t.Errorf("unexpected subject ID: %s", subjectID)
		}
	})

	t.Run("ToBase64Strings", func(t *testing.T) {
		b64Strings := certChain.ToBase64Strings()
		if len(b64Strings) != 2 {
			t.Errorf("expected 2 base64 strings, got %d", len(b64Strings))
		}
		for i, s := range b64Strings {
			if s == "" {
				t.Errorf("empty base64 string at index %d", i)
			}
		}
	})
}

func TestKeyType_Constants(t *testing.T) {
	if KeyTypeJWK != "jwk" {
		t.Errorf("KeyTypeJWK = %s, want 'jwk'", KeyTypeJWK)
	}
	if KeyTypeX5C != "x5c" {
		t.Errorf("KeyTypeX5C = %s, want 'x5c'", KeyTypeX5C)
	}
}

func TestRole_Constants(t *testing.T) {
	if RoleIssuer != "issuer" {
		t.Errorf("RoleIssuer = %s, want 'issuer'", RoleIssuer)
	}
	if RoleVerifier != "verifier" {
		t.Errorf("RoleVerifier = %s, want 'verifier'", RoleVerifier)
	}
	if RoleAny != "" {
		t.Errorf("RoleAny = %s, want ''", RoleAny)
	}
}

func TestLocalTrustEvaluator_SupportsKeyType(t *testing.T) {
	eval := NewLocalTrustEvaluator(LocalTrustConfig{})

	if !eval.SupportsKeyType(KeyTypeX5C) {
		t.Error("expected LocalTrustEvaluator to support X5C")
	}
	if eval.SupportsKeyType(KeyTypeJWK) {
		t.Error("expected LocalTrustEvaluator to not support JWK")
	}
}

func TestEvaluationRequest_GetEffectiveAction(t *testing.T) {
	tests := []struct {
		name   string
		req    *EvaluationRequest
		expect string
	}{
		{
			name:   "explicit action takes precedence",
			req:    &EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Action: "custom-policy", Role: RoleIssuer}},
			expect: "custom-policy",
		},
		{
			name:   "no role returns empty",
			req:    &EvaluationRequest{},
			expect: "",
		},
		{
			name:   "PID issuer becomes pid-provider",
			req:    &EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Role: RoleIssuer, CredentialType: "PID"}},
			expect: "pid-provider",
		},
		{
			name:   "generic issuer with credential type becomes credential-issuer",
			req:    &EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Role: RoleIssuer, CredentialType: "mDL"}},
			expect: "credential-issuer",
		},
		{
			name:   "verifier becomes credential-verifier",
			req:    &EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Role: RoleVerifier}},
			expect: "credential-verifier",
		},
		{
			name:   "wallet provider stays as-is",
			req:    &EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Role: RoleWalletProvider}},
			expect: "wallet_provider",
		},
		{
			name:   "issuer without credential type stays as issuer",
			req:    &EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Role: RoleIssuer}},
			expect: "issuer",
		},
		{
			name:   "mDL docType issuer becomes mdl-issuer",
			req:    &EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Role: RoleCredentialIssuer, DocType: "org.iso.18013.5.1.mDL"}},
			expect: "mdl-issuer",
		},
		{
			name:   "mDL docType verifier becomes mdl-verifier",
			req:    &EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Role: RoleCredentialVerifier, DocType: "org.iso.18013.5.1.mDL"}},
			expect: "mdl-verifier",
		},
		{
			name:   "credential issuer with docType becomes credential-issuer",
			req:    &EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Role: RoleCredentialIssuer, DocType: "org.iso.18013.5.1.PID"}},
			expect: "credential-issuer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.GetEffectiveAction()
			if got != tt.expect {
				t.Errorf("GetEffectiveAction() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestTrustOptions(t *testing.T) {
	opts := &TrustOptions{
		IncludeTrustChain:   true,
		IncludeCertificates: true,
		BypassCache:         true,
	}

	// Verify struct fields
	if !opts.IncludeTrustChain {
		t.Error("expected IncludeTrustChain to be true")
	}
	if !opts.IncludeCertificates {
		t.Error("expected IncludeCertificates to be true")
	}
	if !opts.BypassCache {
		t.Error("expected BypassCache to be true")
	}
}

func TestNewEvaluationRequest(t *testing.T) {
	subjectID := "https://issuer.example.com"
	keyType := KeyTypeJWK
	key := map[string]any{"kty": "EC"}

	req := NewEvaluationRequest(subjectID, keyType, key)

	if req == nil {
		t.Fatal("NewEvaluationRequest returned nil")
	}
	if req.SubjectID != subjectID {
		t.Errorf("SubjectID = %q, want %q", req.SubjectID, subjectID)
	}
	if req.KeyType != keyType {
		t.Errorf("KeyType = %q, want %q", req.KeyType, keyType)
	}
	if req.Key == nil {
		t.Error("Key should not be nil")
	}
}

func TestLocalTrustEvaluator_AddTrustedRoot(t *testing.T) {
	eval := NewLocalTrustEvaluator(LocalTrustConfig{})

	// Initially no trusted roots
	roots := eval.GetTrustedRoots()
	if len(roots) != 0 {
		t.Errorf("expected 0 trusted roots initially, got %d", len(roots))
	}

	// Add a root
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Added Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	eval.AddTrustedRoot(rootCert)

	// Now should have 1 root
	roots = eval.GetTrustedRoots()
	if len(roots) != 1 {
		t.Errorf("expected 1 trusted root after add, got %d", len(roots))
	}
	if roots[0].Subject.CommonName != "Added Root" {
		t.Errorf("unexpected root CN: %s", roots[0].Subject.CommonName)
	}
}

func TestLocalTrustEvaluator_GetTrustedRoots(t *testing.T) {
	chain, rootCert, _ := createTestCertChain(t)
	_ = chain // not used here

	eval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	})

	roots := eval.GetTrustedRoots()
	if len(roots) != 1 {
		t.Errorf("expected 1 trusted root, got %d", len(roots))
	}
}

func TestLocalTrustEvaluator_EmptyCertChain(t *testing.T) {
	_, rootCert, _ := createTestCertChain(t)

	eval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	})

	// Empty certificate chain
	decision, err := eval.Evaluate(t.Context(), &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			KeyType: KeyTypeX5C,
			Key:     []*x509.Certificate{},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Trusted {
		t.Error("expected untrusted for empty cert chain")
	}
	if decision.Reason != "empty certificate chain" {
		t.Errorf("unexpected reason: %s", decision.Reason)
	}
}

func TestLocalTrustEvaluator_CertificateMatchesSubject(t *testing.T) {
	chain, rootCert, _ := createTestCertChain(t)

	eval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	})

	ctx := t.Context()

	tests := []struct {
		name      string
		subjectID string
		trusted   bool
	}{
		{
			name:      "matches CN exactly",
			subjectID: "https://issuer.example.com",
			trusted:   true,
		},
		{
			name:      "does not match CN",
			subjectID: "https://different.example.com",
			trusted:   false,
		},
		{
			name:      "empty subject ID (no validation)",
			subjectID: "",
			trusted:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := eval.Evaluate(ctx, &EvaluationRequest{
				EvaluationRequest: trustapi.EvaluationRequest{
					SubjectID: tt.subjectID,
					KeyType:   KeyTypeX5C,
					Key:       chain,
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if decision.Trusted != tt.trusted {
				t.Errorf("Trusted = %v, want %v (reason: %s)", decision.Trusted, tt.trusted, decision.Reason)
			}
		})
	}
}

func TestLocalTrustEvaluator_X5CCertChainType(t *testing.T) {
	chain, rootCert, _ := createTestCertChain(t)

	eval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	})

	// Use X5CCertChain type explicitly
	certChain := X5CCertChain(chain)

	decision, err := eval.Evaluate(t.Context(), &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeX5C,
			Key:       certChain,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Trusted {
		t.Errorf("expected trusted, got: %s", decision.Reason)
	}
}

func TestLocalTrustEvaluator_InvalidX5CKeyType(t *testing.T) {
	_, rootCert, _ := createTestCertChain(t)

	eval := NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	})

	// Invalid key type for X5C
	_, err := eval.Evaluate(t.Context(), &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			KeyType: KeyTypeX5C,
			Key:     "not-a-cert-chain",
		},
	})

	if err == nil {
		t.Error("expected error for invalid X5C key type")
	}
}

func TestTrustFrameworkNone_Constant(t *testing.T) {
	if TrustFrameworkNone != "none" {
		t.Errorf("TrustFrameworkNone = %q, want 'none'", TrustFrameworkNone)
	}
}

func TestErrMsgNilRequest_Constant(t *testing.T) {
	if ErrMsgNilRequest != "evaluation request is nil" {
		t.Errorf("ErrMsgNilRequest = %q, want 'evaluation request is nil'", ErrMsgNilRequest)
	}
}

func TestCompositeEvaluator_AllMustSucceed(t *testing.T) {
	chain, rootCert, _ := createTestCertChain(t)
	ctx := t.Context()

	t.Run("all evaluators accept", func(t *testing.T) {
		eval1 := NewLocalTrustEvaluator(LocalTrustConfig{
			TrustedRoots: []*x509.Certificate{rootCert},
		})
		eval2 := NewLocalTrustEvaluator(LocalTrustConfig{
			TrustedRoots: []*x509.Certificate{rootCert},
		})

		composite := NewCompositeEvaluator(StrategyAllMustSucceed, eval1, eval2)

		decision, err := composite.Evaluate(ctx, &EvaluationRequest{
			EvaluationRequest: trustapi.EvaluationRequest{
				SubjectID: "https://issuer.example.com",
				KeyType:   KeyTypeX5C,
				Key:       chain,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !decision.Trusted {
			t.Errorf("expected trusted, got: %s", decision.Reason)
		}
	})

	t.Run("one evaluator rejects", func(t *testing.T) {
		accepting := NewLocalTrustEvaluator(LocalTrustConfig{
			TrustedRoots: []*x509.Certificate{rootCert},
		})
		rejecting := NewLocalTrustEvaluator(LocalTrustConfig{
			TrustedRoots: []*x509.Certificate{}, // Empty, will reject
		})

		composite := NewCompositeEvaluator(StrategyAllMustSucceed, accepting, rejecting)

		decision, err := composite.Evaluate(ctx, &EvaluationRequest{
			EvaluationRequest: trustapi.EvaluationRequest{
				SubjectID: "https://issuer.example.com",
				KeyType:   KeyTypeX5C,
				Key:       chain,
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Trusted {
			t.Error("expected untrusted when one evaluator rejects")
		}
	})

	t.Run("no evaluator supports key type", func(t *testing.T) {
		eval := NewLocalTrustEvaluator(LocalTrustConfig{
			TrustedRoots: []*x509.Certificate{rootCert},
		})
		// LocalTrustEvaluator only supports X5C
		composite := NewCompositeEvaluator(StrategyAllMustSucceed, eval)

		_, err := composite.Evaluate(ctx, &EvaluationRequest{
			EvaluationRequest: trustapi.EvaluationRequest{
				SubjectID: "https://issuer.example.com",
				KeyType:   KeyTypeJWK,
				Key:       map[string]any{"kty": "EC"},
			},
		})

		if err == nil {
			t.Error("expected error when no evaluator supports key type")
		}
	})
}

func TestCompositeEvaluator_AddEvaluator(t *testing.T) {
	chain, rootCert, _ := createTestCertChain(t)
	ctx := t.Context()

	composite := NewCompositeEvaluator(StrategyFirstSuccess)

	// Initially no evaluators - should fail
	_, err := composite.Evaluate(ctx, &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeX5C,
			Key:       chain,
		},
	})
	if err == nil {
		t.Error("expected error with no evaluators")
	}

	// Add evaluator dynamically
	composite.AddEvaluator(NewLocalTrustEvaluator(LocalTrustConfig{
		TrustedRoots: []*x509.Certificate{rootCert},
	}))

	decision, err := composite.Evaluate(ctx, &EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: "https://issuer.example.com",
			KeyType:   KeyTypeX5C,
			Key:       chain,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Trusted {
		t.Error("expected trusted after adding evaluator")
	}
}

func TestJwkToEd25519(t *testing.T) {
	// Generate a real Ed25519 key
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	xB64 := base64.RawURLEncoding.EncodeToString(pubKey)

	t.Run("valid Ed25519 JWK", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   xB64,
		}
		got, err := jwkToEd25519(jwk)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !pubKey.Equal(got) {
			t.Error("keys don't match")
		}
	})

	t.Run("wrong key type", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "EC",
			"crv": "Ed25519",
			"x":   xB64,
		}
		_, err := jwkToEd25519(jwk)
		if err == nil {
			t.Error("expected error for wrong kty")
		}
	})

	t.Run("wrong curve", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "OKP",
			"crv": "X25519",
			"x":   xB64,
		}
		_, err := jwkToEd25519(jwk)
		if err == nil {
			t.Error("expected error for wrong curve")
		}
	})

	t.Run("missing x coordinate", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
		}
		_, err := jwkToEd25519(jwk)
		if err == nil {
			t.Error("expected error for missing x")
		}
	})

	t.Run("invalid base64 x coordinate", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   "!!!invalid!!!",
		}
		_, err := jwkToEd25519(jwk)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("wrong key size", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString([]byte("short")),
		}
		_, err := jwkToEd25519(jwk)
		if err == nil {
			t.Error("expected error for wrong key size")
		}
	})
}

func TestDecodeMultibaseKey(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, err := decodeMultibaseKey("z")
		if err == nil {
			t.Error("expected error for short input")
		}
	})

	t.Run("base58-btc not implemented", func(t *testing.T) {
		_, err := decodeMultibaseKey("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
		if err == nil {
			t.Error("expected error for base58-btc")
		}
	})

	t.Run("unsupported encoding", func(t *testing.T) {
		_, err := decodeMultibaseKey("xsomething")
		if err == nil {
			t.Error("expected error for unsupported encoding")
		}
	})
}

func TestExtractKeyFromJWK(t *testing.T) {
	t.Run("unsupported key type", func(t *testing.T) {
		_, err := extractKeyFromJWK(map[string]any{"kty": "RSA"})
		if err == nil {
			t.Error("expected error for unsupported key type")
		}
	})

	t.Run("EC key type delegates to jwkToECDSA", func(t *testing.T) {
		// Minimal invalid EC JWK - will fail inside jwkToECDSA
		_, err := extractKeyFromJWK(map[string]any{"kty": "EC"})
		if err == nil {
			t.Error("expected error for invalid EC JWK")
		}
	})

	t.Run("OKP key type delegates to jwkToEd25519", func(t *testing.T) {
		// Invalid OKP JWK - missing crv
		_, err := extractKeyFromJWK(map[string]any{"kty": "OKP"})
		if err == nil {
			t.Error("expected error for invalid OKP JWK")
		}
	})
}
