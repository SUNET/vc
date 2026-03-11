//go:build zk

package apiv1

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestVerifyZKP(t *testing.T) {
    ctx := t.Context()
    transcript := "g/b2gnZPcGVuSUQ0VlBEQ0FQSUhhbmRvdmVyWCC+g0qI5l1IQfgYZpodKs/I+r9axTucmuRDCE4W/HiSvQ=="
    deviceCBOR := "o2ZzdGF0dXMA..." // Full string here

    tests := []struct {
        name        string
        req         *VerifyZKPRequest
        expectError bool
    }{
        {
            name: "process valid base64 payload",
            req: &VerifyZKPRequest{
                Transcript:           transcript,
                ZKDeviceResponseCBOR: deviceCBOR,
            },
            expectError: false,
        },
        {
            name: "fail on malformed base64 transcript",
            req: &VerifyZKPRequest{
                Transcript:           "invalid-base64-!@#",
                ZKDeviceResponseCBOR: deviceCBOR,
            },
            expectError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            client, _ := CreateTestClientWithMock(nil)
            resp, err := client.VerifyZKP(ctx, tt.req)

            if tt.expectError {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                require.NotNil(t, resp)
                _, ok := resp.Claims["org.iso.18013.5.1"]
                assert.True(t, ok)
            }
        })
    }
}