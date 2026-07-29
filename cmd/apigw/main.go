package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	authproviders "github.com/SUNET/vc/internal/apigw/auth_providers"
	"github.com/SUNET/vc/internal/apigw/cache"
	datasources "github.com/SUNET/vc/internal/apigw/data_sources"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/internal/apigw/httpserver"
	"github.com/SUNET/vc/internal/apigw/importer"
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

	if cfg.APIGW.DataSources.Datastore.Import != nil {
		if err := importer.RunDocuments(ctx, cfg.APIGW.DataSources.Datastore.Import, dbService, log); err != nil {
			mainLog.Error(err, "Document import failed")
		}
	}

	if cfg.APIGW.IdentityMappingImport != nil {
		if err := importer.RunIdentityMappings(ctx, cfg.APIGW.IdentityMappingImport, dbService, log); err != nil {
			mainLog.Error(err, "Identity mapping import failed")
		}
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

	// Start background refresher for signed metadata (issuer-signed, cached with 1h TTL)
	apiv1Client.StartSignedMetadataRefresher(ctx)

	// Initialize auth providers (SAML, OIDC)
	authProvidersSvc, err := authproviders.New(ctx, &cfg.APIGW.AuthProviders, cacheService.SAMLSession, cacheService.OIDCRPSession, dbService, mainLog)
	if err != nil {
		panic(err)
	}

	// Initialize data sources (Edu-API, etc.)
	dataSourcesSvc, err := datasources.New(ctx, cfg.APIGW.Remotes, cacheService.Document, mainLog)
	if err != nil {
		panic(err)
	}

	httpService, err := httpserver.New(ctx, cfg, apiv1Client, tracer, eventPublisher, authProvidersSvc, dataSourcesSvc, cacheService, log)
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
