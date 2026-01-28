package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"vc/internal/registry/apiv1"
	"vc/internal/registry/db"
	"vc/internal/registry/grpcserver"
	"vc/internal/registry/httpserver"
	"vc/internal/registry/tokenstatuslistissuer"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

type service interface {
	Close(ctx context.Context) error
}

func main() {
	var (
		ctx                = context.Background()
		services           = make(map[string]service)
		serviceName string = "registry"
	)

	cfg, err := configuration.New(ctx)
	if err != nil {
		panic(err)
	}

	if cfg.Registry == nil {
		panic("registry configuration is required but not found in config file")
	}

	log, err := logger.New(serviceName, cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}

	// main function log
	mainLog := log.New("main")

	tracer, err := trace.New(ctx, cfg, serviceName, log)
	if err != nil {
		panic(err)
	}

	dbService, err := db.New(ctx, cfg, tracer, log)
	services["dbService"] = dbService
	if err != nil {
		panic(err)
	}

	tokenStatusListIssuerService, err := tokenstatuslistissuer.New(ctx, cfg, dbService, log)
	services["tokenStatusListIssuerService"] = tokenStatusListIssuerService
	if err != nil {
		panic(err)
	}

	apiv1Client, err := apiv1.New(ctx, cfg, tokenStatusListIssuerService, dbService, log)
	if err != nil {
		panic(err)
	}

	grpcService, err := grpcserver.New(ctx, tokenStatusListIssuerService, apiv1Client, cfg, log)
	services["grpcService"] = grpcService
	if err != nil {
		panic(err)
	}

	httpService, err := httpserver.New(ctx, cfg, apiv1Client, tracer, log)
	services["httpService"] = httpService
	if err != nil {
		panic(err)
	}

	// Handle sigterm and await termChan signal
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan // Blocks here until interrupted

	mainLog.Info("HALTING SIGNAL!")

	for serviceName, service := range services {
		if err := service.Close(ctx); err != nil {
			mainLog.Error(err, "serviceName", serviceName)
		}
	}

	if err := tracer.Shutdown(ctx); err != nil {
		mainLog.Error(err, "Tracer shutdown")
	}

	mainLog.Info("Stopped")
}
