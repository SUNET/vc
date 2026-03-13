//go:build zk
package apiv1

import (
    "context"
    "encoding/base64"
    "encoding/hex"
    "fmt"

    "proofs/server/v2/zk"
)

func (c *Client) VerifyZKP(ctx context.Context, req *VerifyZKPRequest) (*VerifyZKPResponse, error) {
	c.log.Debug("Processing ZK Proof", "transcript_len", len(req.Transcript))
	transcriptBytes, err := base64.StdEncoding.DecodeString(req.Transcript)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transcript: %w", err)
	}

	cborBytes, err := base64.StdEncoding.DecodeString(req.ZKDeviceResponseCBOR)
	if err != nil {
		return nil, fmt.Errorf("failed to decode device response: %w", err)
	}

	vreq, err := zk.ProcessDeviceResponse(cborBytes)
	if err != nil {
		c.log.Error(err, "CBOR processing failed")
		return nil, fmt.Errorf("error processing cbor request: %w", err)
	}

	vreq.Transcript = transcriptBytes
	ok, err := zk.VerifyProofRequest(vreq)

	apiClaims := make([]ClaimElement, 0)

	for _, items := range vreq.Claims {
		for _, item := range items {
			hexValue := hex.EncodeToString(item.ElementValue)

			apiClaims = append(apiClaims, ClaimElement{
				ElementIdentifier: item.ElementIdentifier,
				ElementValue:      hexValue,
			})
		}
	}

	//TODO: support more vc types
	reply := &VerifyZKPResponse{
		Status: ok,
		Claims: map[string][]ClaimElement{
			"org.iso.18013.5.1": apiClaims,
		},
	}

	if err != nil {
		c.log.Error(err, "invalid proof detected")
	}

	return reply, nil
}
