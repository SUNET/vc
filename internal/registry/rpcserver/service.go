package rpcserver

import (
	"context"
	"net"
	apiv1_registry "vc/internal/gen/registry/apiv1.registry"
	"vc/internal/registry/apiv1"
	"vc/pkg/logger"
	"vc/pkg/model"

	"google.golang.org/grpc"
)

// Service is the service object for rpcserver
type Service struct {
	apiv1      Apiv1
	log        *logger.Log
	cfg        *model.Cfg
	listener   net.Listener
	grpcServer *grpc.Server
	apiv1_registry.RegistryServiceServer
}

// New creates a new rpcserver service
func New(ctx context.Context, api *apiv1.Client, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		log:        log,
		cfg:        cfg,
		grpcServer: grpc.NewServer(),
	}

	var err error
	s.listener, err = net.Listen("tcp", cfg.Registry.RPCServer.Addr)
	if err != nil {
		return nil, err
	}

	apiv1_registry.RegisterRegistryServiceServer(s.grpcServer, s)
	go func() {
		if err := s.grpcServer.Serve(s.listener); err != nil {
			s.log.Error(err, "failed to serve")
		}
	}()

	s.log.Info("Started")

	return s, nil
}

// Close closes the service
func (s *Service) Close(ctx context.Context) error {
	return nil
}