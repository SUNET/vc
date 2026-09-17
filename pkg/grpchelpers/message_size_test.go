package grpchelpers

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apiv1_issuer "github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/model"
)

// echoIssuer answers MakeSDJWT with a payload the size of the one it received,
// so a round trip exercises the limit in both directions.
type echoIssuer struct {
	apiv1_issuer.UnimplementedIssuerServiceServer
}

func (echoIssuer) MakeSDJWT(_ context.Context, req *apiv1_issuer.MakeSDJWTRequest) (*apiv1_issuer.MakeSDJWTReply, error) {
	return &apiv1_issuer.MakeSDJWTReply{
		Credentials: []*apiv1_issuer.Credential{{Credential: string(req.GetDocumentData())}},
	}, nil
}

// serveEcho starts an echo issuer on a random port using the real server
// options, and returns a client built with the real client constructor.
func serveEcho(t *testing.T) apiv1_issuer.IssuerServiceClient {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	opts, err := NewServerOptions(model.GRPCServer{Addr: lis.Addr().String()})
	require.NoError(t, err)

	srv := grpc.NewServer(opts...)
	apiv1_issuer.RegisterIssuerServiceServer(srv, echoIssuer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := NewClientConn(model.GRPCClientTLS{Addr: lis.Addr().String()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return apiv1_issuer.NewIssuerServiceClient(conn)
}

// TestMessageSize_AboveGRPCDefault is the regression this limit exists for:
// Credential Issuer Metadata outgrew grpc-go's 4 MiB default, and an issuer
// could no longer sign its own metadata. A payload between that default and
// MaxMessageBytes must now cross intact, request and response alike.
func TestMessageSize_AboveGRPCDefault(t *testing.T) {
	client := serveEcho(t)

	const payload = 6 * 1024 * 1024 // above grpc-go's 4 MiB default, below ours
	require.Greater(t, payload, 4*1024*1024)
	require.Less(t, payload, MaxMessageBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reply, err := client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		DocumentData: make([]byte, payload),
	})
	require.NoError(t, err, "a payload under MaxMessageBytes must not be refused by the transport")
	require.Len(t, reply.GetCredentials(), 1)
	assert.Len(t, reply.GetCredentials()[0].GetCredential(), payload, "the response must come back at full size too")
}

// TestMessageSize_AboveOurLimit shows the limit is a real bound rather than
// an unlimited connection: past MaxMessageBytes the transport still refuses.
func TestMessageSize_AboveOurLimit(t *testing.T) {
	client := serveEcho(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		DocumentData: make([]byte, MaxMessageBytes+1024),
	})
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}
