package trust_test

import (
	"context"
	"fmt"

	"github.com/SUNET/vc/pkg/trust"
)

func ExampleNewAllowAllEvaluator() {
	evaluator := trust.NewAllowAllEvaluator()
	fmt.Printf("%T\n", evaluator)
	// Output:
	// *trust.AllowAllEvaluator
}

func ExampleAllowAllEvaluator_Evaluate() {
	ctx := context.Background()
	evaluator := trust.NewAllowAllEvaluator()

	req := trust.NewEvaluationRequest("https://issuer.example.com", trust.KeyTypeJWK, nil)
	decision, err := evaluator.Evaluate(ctx, req)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("trusted:", decision.Trusted)
	fmt.Println("reason:", decision.Reason)
	fmt.Println("framework:", decision.TrustFramework)
	// Output:
	// trusted: true
	// reason: allow all mode: no PDP configured
	// framework: none
}

func ExampleAllowAllEvaluator_SupportsKeyType() {
	evaluator := trust.NewAllowAllEvaluator()

	fmt.Println("supports JWK:", evaluator.SupportsKeyType(trust.KeyTypeJWK))
	fmt.Println("supports X5C:", evaluator.SupportsKeyType(trust.KeyTypeX5C))
	// Output:
	// supports JWK: true
	// supports X5C: true
}

func ExampleNewEvaluationRequest() {
	req := trust.NewEvaluationRequest(
		"https://issuer.example.com",
		trust.KeyTypeJWK,
		nil,
	)

	fmt.Println("subject:", req.SubjectID)
	fmt.Println("key type:", req.KeyType)
	// Output:
	// subject: https://issuer.example.com
	// key type: jwk
}

func ExampleEvaluationRequest_GetEffectiveAction() {
	// With explicit role set
	req := trust.NewEvaluationRequest("https://issuer.example.com", trust.KeyTypeJWK, nil)
	req.Role = trust.RoleIssuer
	req.CredentialType = "PID"

	fmt.Println("PID issuer action:", req.GetEffectiveAction())

	// With a verifier role
	req2 := trust.NewEvaluationRequest("https://verifier.example.com", trust.KeyTypeJWK, nil)
	req2.Role = trust.RoleVerifier

	fmt.Println("verifier action:", req2.GetEffectiveAction())
	// Output:
	// PID issuer action: pid-provider
	// verifier action: credential-verifier
}

func ExampleNewCompositeEvaluator() {
	ctx := context.Background()

	// Create a composite evaluator with two AllowAll evaluators using FirstSuccess strategy
	eval1 := trust.NewAllowAllEvaluator()
	eval2 := trust.NewAllowAllEvaluator()
	composite := trust.NewCompositeEvaluator(trust.StrategyFirstSuccess, eval1, eval2)

	req := trust.NewEvaluationRequest("https://issuer.example.com", trust.KeyTypeJWK, nil)
	decision, err := composite.Evaluate(ctx, req)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("trusted:", decision.Trusted)
	fmt.Println("supports JWK:", composite.SupportsKeyType(trust.KeyTypeJWK))
	// Output:
	// trusted: true
	// supports JWK: true
}

func ExampleNewTrustEvaluatorFromConfig() {
	// Empty PDP URL returns an AllowAll evaluator
	evaluator := trust.NewTrustEvaluatorFromConfig("")
	fmt.Printf("%T\n", evaluator)
	// Output:
	// *trust.AllowAllEvaluator
}
