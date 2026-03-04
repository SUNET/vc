//go:build vc20
// +build vc20

package trust

import (
	"testing"
)

func TestNewTrustEvaluatorFromConfig_NoPDP(t *testing.T) {
	// When no PDP URL is provided, should return AllowAllEvaluator
	eval := NewTrustEvaluatorFromConfig("")

	_, ok := eval.(*AllowAllEvaluator)
	if !ok {
		t.Errorf("expected AllowAllEvaluator when pdpURL is empty, got %T", eval)
	}
}

func TestNewTrustEvaluatorFromConfig_WithPDP(t *testing.T) {
	// When PDP URL is provided, should return GoTrustEvaluator
	eval := NewTrustEvaluatorFromConfig("https://pdp.example.com")

	_, ok := eval.(*GoTrustEvaluator)
	if !ok {
		t.Errorf("expected GoTrustEvaluator when pdpURL is set, got %T", eval)
	}
}
