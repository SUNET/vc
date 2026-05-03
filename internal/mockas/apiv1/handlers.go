package apiv1

import (
	"context"
	"errors"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"
)

// MockNext sends one mock upload to the datastore
func (c *Client) MockNext(ctx context.Context, inData *vcclient.MockNextRequest) (*vcclient.MockNextReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:MockNext")
	defer span.End()

	mockUpload, err := c.mockOne(ctx, inData)
	if err != nil {
		return nil, err
	}

	resp, err := c.uploader(ctx, mockUpload)
	if err != nil {
		c.log.Error(err, "failed to upload", "mockUpload", mockUpload)
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New("upload failed")
	}

	reply := &vcclient.MockNextReply{
		Upload: map[string]any{
			"meta":          mockUpload.Meta,
			"identities":    mockUpload.Identities,
			"document_data": mockUpload.DocumentData,
		},
	}

	return reply, nil
}

// MockBulk sends N mock uploads to the datastore
func (c *Client) MockBulk(ctx context.Context, inData *vcclient.MockBulkRequest) (*vcclient.MockBulkReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:MockBulk")
	defer span.End()

	documentIDS := []string{}

	if inData.N < 1 {
		return nil, errors.New("n must be greater than 0")
	}

	for i := 0; i < inData.N; i++ {
		mockUpload, err := c.mockOne(ctx, &inData.MockNextRequest)
		if err != nil {
			return nil, err
		}
		documentIDS = append(documentIDS, mockUpload.Meta.DocumentID)

		resp, err := c.uploader(ctx, mockUpload)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != 200 {
			return nil, errors.New("upload failed")
		}
	}

	return &vcclient.MockBulkReply{
		DocumentIDS: documentIDS,
	}, nil
}

// Health returns the status of the service
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	_, span := c.tracer.Start(ctx, "apiv1:Health")
	defer span.End()

	probes := model.Probes{}
	status := probes.Check("mockas")
	return status, nil
}
