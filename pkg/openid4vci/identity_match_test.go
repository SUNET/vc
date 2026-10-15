package openid4vci

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The refusal has to point somewhere a caller can actually go.
//
// It used to say "omit the match to prepare an unbound issuance", which
// cannot work: PrepareIssuance marks identity_match required, so omitting
// it is refused as a missing field rather than honoured as a choice. A
// caller following that advice gets a second error and no unbound
// issuance. The thing it was describing is the pre-authorized grant,
// which is a different request.
func TestIdentityMatchRefusalNamesTheRightAlternative(t *testing.T) {
	err := (&IdentityMatch{}).Validate()
	require.Error(t, err)

	assert.Contains(t, err.Error(), "pre-authorized grant",
		"the refusal must name the request that does provide an unbound issuance")
	assert.NotContains(t, err.Error(), "omit the match",
		"omitting identity_match is refused as a missing field, so it is not advice")

	// A nil rule is the same refusal, and must carry the same guidance.
	var nilMatch *IdentityMatch
	nilErr := nilMatch.Validate()
	require.Error(t, nilErr)
	assert.Equal(t, err.Error(), nilErr.Error())
}
