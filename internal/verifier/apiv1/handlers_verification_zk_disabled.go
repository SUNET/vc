//go:build !zk

package apiv1

import (
    "context"
    "fmt"
)

func (c *Client) VerifyZKP(ctx context.Context, req *VerifyZKPRequest) (*VerifyZKPResponse, error) {
    c.log.Error(nil, "VerifyZKP called but ZK support is disabled", "id", req.Transcript)
    
    // Using your requested error string
    return nil, fmt.Errorf("no item in credential cache matching id %s", req.Transcript)
}