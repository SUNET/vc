package apiv1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/url"
	"testing"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/internal/issuer/auditlog"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/pki"
	"vc/pkg/trace"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

// mockRegistryClient implements apiv1_registry.RegistryServiceClient for testing
type mockRegistryClient struct {
	section int64
	index   int64
}

func (m *mockRegistryClient) TokenStatusListAddStatus(ctx context.Context, in *apiv1_registry.TokenStatusListAddStatusRequest, opts ...grpc.CallOption) (*apiv1_registry.TokenStatusListAddStatusReply, error) {
	m.index++
	u, _ := url.Parse("https://test-registry.sunet.se")
	u.Path, _ = url.JoinPath(u.Path, "statuslists", fmt.Sprintf("%d", m.section))
	return &apiv1_registry.TokenStatusListAddStatusReply{
		Section:       m.section,
		Index:         m.index,
		StatusListUri: u.String(),
	}, nil
}

func (m *mockRegistryClient) TokenStatusListUpdateStatus(ctx context.Context, in *apiv1_registry.TokenStatusListUpdateStatusRequest, opts ...grpc.CallOption) (*apiv1_registry.TokenStatusListUpdateStatusReply, error) {
	return &apiv1_registry.TokenStatusListUpdateStatusReply{}, nil
}

func (m *mockRegistryClient) SaveCredentialSubject(ctx context.Context, in *apiv1_registry.SaveCredentialSubjectRequest, opts ...grpc.CallOption) (*apiv1_registry.SaveCredentialSubjectReply, error) {
	return &apiv1_registry.SaveCredentialSubjectReply{}, nil
}

func mockNewClient(ctx context.Context, t *testing.T, keyType string, log *logger.Log) *Client {
	cfg := &model.Cfg{
		Common: &model.Common{},
		Issuer: &model.Issuer{
			APIServer:  model.APIServer{},
			GRPCServer: model.GRPCServer{},
			KeyConfig: &pki.KeyConfig{
				PrivateKeyPath: "testdata/signing_test.key",
			},
			JWTAttribute: model.JWTAttribute{
				Issuer:                   "https://test-issuer.sunet.se",
				EnableNotBefore:          false,
				ValidDuration:            0,
				VerifiableCredentialType: "",
				Status:                   "",
				Kid:                      "",
			},
		},
	}

	tracer, err := trace.NewForTesting(ctx, "test", log.New("trace"))
	assert.NoError(t, err)

	audit, err := auditlog.New(ctx, cfg, log.New("audit"))
	assert.NoError(t, err)

	client, err := New(ctx, audit, cfg, tracer, log.New("apiv1"))
	assert.NoError(t, err)

	// Inject mock registry client for Token Status List allocation
	client.registryClient = &mockRegistryClient{section: 0, index: 0}

	// Override key if RSA is requested for testing
	if keyType == "rsa" {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NoError(t, err)
		client.privateKey = rsaKey
		// Also update the signer to use RSA
		signer, err := pki.NewSoftwareSigner(rsaKey, "test-rsa-kid")
		assert.NoError(t, err)
		client.signer = signer
	}

	return client
}
