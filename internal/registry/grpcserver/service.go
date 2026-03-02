package grpcserver

import (
	"context"
	"fmt"
	"net"
	"vc/internal/gen/registry/apiv1_registry"
	"vc/pkg/grpchelpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"google.golang.org/grpc"
)

// Service is the service object for grpcserver
type Service struct {
	tokenStatusListIssuer TokenStatusListIssuer
	apiv1                 Apiv1
	log                   *logger.Log
	cfg                   *model.Cfg
	listener              net.Listener
	grpcServer            *grpc.Server
	apiv1_registry.RegistryServiceServer
}

// New creates a new gRPC server service
func New(ctx context.Context, tokenStatusListIssuer TokenStatusListIssuer, apiv1 Apiv1, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		log:                   log.New("grpcserver"),
		cfg:                   cfg,
		tokenStatusListIssuer: tokenStatusListIssuer,
		apiv1:                 apiv1,
	}

	// Configure server options using helper
	opts, err := grpchelpers.NewServerOptions(cfg.Registry.GRPCServer)
	if err != nil {
		return nil, fmt.Errorf("failed to configure gRPC server options: %w", err)
	}

	s.grpcServer = grpc.NewServer(opts...)

	s.listener, err = net.Listen("tcp", cfg.Registry.GRPCServer.Addr)
	if err != nil {
		return nil, err
	}

	apiv1_registry.RegisterRegistryServiceServer(s.grpcServer, s)
	go func() {
		if err := s.grpcServer.Serve(s.listener); err != nil {
			s.log.Error(err, "failed to serve")
		}
	}()

	if cfg.Registry.GRPCServer.TLS.Enable {
		s.log.Info("Started", "tls", "mTLS enabled")
	} else {
		s.log.Info("Started", "tls", "disabled (insecure)")
	}

	return s, nil
}

// Close closes the service
func (s *Service) Close(ctx context.Context) error {
	s.listener.Close()
	s.grpcServer.Stop()
	s.log.Info("Stopped")
	return nil
}
