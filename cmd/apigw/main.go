package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/internal/apigw/apiv2"
	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/internal/apigw/httpserver"
	"github.com/SUNET/vc/internal/apigw/inbound"
	"github.com/SUNET/vc/internal/apigw/outbound"
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
		wg                 = &sync.WaitGroup{}
		ctx                = context.Background()
		services           = make(map[string]service)
		serviceName string = "apigw"
	)

	cfg, err := configuration.New(ctx, serviceName)
	if err != nil {
		panic(err)
	}

	if cfg.APIGW == nil {
		panic("apigw configuration is required but not found in config file")
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

	var eventPublisher apiv1.EventPublisher
	if cfg.Common.Kafka.Enable {
		var err error
		eventPublisher, err = outbound.New(ctx, cfg, tracer, log)
		services["eventPublisher"] = eventPublisher
		if err != nil {
			panic(err)
		}
	} else {
		mainLog.Info("EventPublisher disabled in config")
	}

	apiv1Client, err := apiv1.New(ctx, dbService, cacheService, tracer, cfg, log)
	if err != nil {
		panic(err)
	}

	apiv2Client, err := apiv2.New(ctx, dbService, tracer, cfg, log)
	if err != nil {
		panic(err)
	}

	// Initialize SAML service if enabled
	samlSPService, err := initSAMLSPService(ctx, cfg, cacheService, mainLog)
	if err != nil {
		mainLog.Error(err, "Failed to initialize SAML service")
		panic(err)
	}

	// Initialize OIDC RP service if enabled
	oidcrpService, err := initOIDCRPService(ctx, cfg, cacheService, dbService, mainLog)
	if err != nil {
		mainLog.Error(err, "Failed to initialize OIDC RP service")
		panic(err)
	}

	httpService, err := httpserver.New(ctx, cfg, apiv1Client, apiv2Client, tracer, eventPublisher, samlSPService, oidcrpService, cacheService, log)
	services["httpService"] = httpService
	if err != nil {
		panic(err)
	}

	if cfg.Common.Kafka.Enable {
		eventConsumer, err := inbound.New(ctx, cfg, apiv1Client, tracer, log.New("eventConsumer"))
		services["eventConsumer"] = eventConsumer
		if err != nil {
			panic(err)
		}
	}

	// Handle sigterm and await termChan signal
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan // Blocks here until interrupted

	mainLog.Info("HALTING SIGNAL!")

	for serviceName, service := range services {
		if err := service.Close(ctx); err != nil {
			mainLog.Trace("serviceName", serviceName, "error", err)
		}
	}

	if err := tracer.Shutdown(ctx); err != nil {
		mainLog.Error(err, "Tracer shutdown")
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}
