package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"github.com/SUNET/vc/internal/registry/apiv1"
	"github.com/SUNET/vc/internal/registry/cache"
	"github.com/SUNET/vc/internal/registry/db"
	"github.com/SUNET/vc/internal/registry/grpcserver"
	"github.com/SUNET/vc/internal/registry/httpserver"
	"github.com/SUNET/vc/internal/registry/tokenstatuslistissuer"
	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
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

	cfg, err := configuration.New(ctx, serviceName)
	if err != nil {
		panic(err)
	}

	if cfg.Registry == nil {
		panic("registry configuration is required but not found in config file")
	}

	log, err := logger.New(serviceName, cfg.Common.Log.FolderPath, model.BoolVal(cfg.Common.Production, true))
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

	cacheService, err := cache.New(ctx, cfg, dbService, tracer, log)
	if err != nil {
		panic(err)
	}

	tokenStatusListIssuerService, err := tokenstatuslistissuer.New(ctx, cfg, cacheService, dbService, log)
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

	httpService, err := httpserver.New(ctx, cfg, apiv1Client, tracer, cacheService, log)
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
