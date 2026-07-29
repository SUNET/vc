package grpcserver

import (
	"context"
	"net"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/internal/issuer/apiv1"
	"github.com/SUNET/vc/pkg/grpchelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"google.golang.org/grpc"
)

// Service holds the service
type Service struct {
	log   *logger.Log
	cfg   *model.Cfg
	apiv1 Apiv1
	apiv1_issuer.UnimplementedIssuerServiceServer
	server *grpc.Server
}

// New creates a new grpc service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, log *logger.Log) (*Service, error) {
	s := &Service{
		log:   log.New("grpcserver"),
		cfg:   cfg,
		apiv1: apiv1,
	}

	listener, err := net.Listen("tcp", s.cfg.Issuer.GRPCServer.Addr)
	if err != nil {
		s.log.Error(err, "failed to listen", "addr", s.cfg.Issuer.GRPCServer.Addr)
	}

	opts, err := grpchelpers.NewServerOptions(s.cfg.Issuer.GRPCServer)
	if err != nil {
		s.log.Error(err, "failed to create gRPC server options")
		return nil, err
	}

	s.server = grpc.NewServer(opts...)
	apiv1_issuer.RegisterIssuerServiceServer(s.server, s)
	s.log.Info("gRPC server listening")
	if err := s.server.Serve(listener); err != nil {
		s.log.Error(err, "failed to serve")
	}

	s.log.Info("Started")
	return s, nil
}

// Close closes gRPC server
func (s *Service) Close(ctx context.Context) error {
	s.server.GracefulStop()
	s.log.Info("Stopped")
	return nil
}
