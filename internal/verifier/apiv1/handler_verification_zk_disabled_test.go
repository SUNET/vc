//go:build !zk

package apiv1

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestVerifyZKP_Disabled(t *testing.T) {
    client, _ := CreateTestClientWithMock(nil)
    req := &VerifyZKPRequest{Transcript: "test-id"}

    resp, err := client.VerifyZKP(t.Context(), req)

    assert.Nil(t, resp)
    assert.Error(t, err)
    // Verify it matches your specific requirement
    assert.Contains(t, err.Error(), "no item in credential cache matching id test-id")
}