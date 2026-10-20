package cache

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

// An Interactive Authorization exchange is an authorization context with a
// handle on it, so it cannot be configured to last longer than the context
// survives - the wallet would come back to find its auth_session gone with
// nothing having gone wrong.
//
// pkg/model cannot import this package to read AuthContextTTL, so the
// ceiling is a constant there and this is what stops the two drifting:
// shorten AuthContextTTL without lowering MaxAuthSessionTTLSeconds and
// this fails, which is the moment to decide which of the two was meant.
func TestAuthContextTTLCoversTheLongestAuthSession(t *testing.T) {
	assert.GreaterOrEqual(t, AuthContextTTL, time.Duration(model.MaxAuthSessionTTLSeconds)*time.Second,
		"an auth_session may be configured to outlive the context it is stored on")
}
