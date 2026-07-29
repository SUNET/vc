package openid4vp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func TestUnwrapVPToken(t *testing.T) {
	tts := []struct {
		name        string
		vpTokenPath string
	}{
		{ // #nosec G101
			name:        "Valid VPToken",
			vpTokenPath: "vp_token_2.golden",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			have := golden.Get(t, tt.vpTokenPath)
			responseParameters := &ResponseParameters{
				VPToken: string(have),
			}

			got, err := responseParameters.BuildCredential()
			assert.NoError(t, err, "Unwrapping VPToken should not return an error")

			fmt.Println("Unwrapped VPToken:", got)
		})
	}
}
