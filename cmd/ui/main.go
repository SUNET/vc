package main

import (
	"context"
	"encoding/gob"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"vc/internal/ui/apiv1"
	"vc/internal/ui/cache"
	"vc/internal/ui/httpserver"
	"vc/internal/ui/outbound"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

func init() {
	// Needed to serialize/deserialize time.Time in the session and cookie
	gob.Register(time.Time{})
}

type service interface {
	Close(ctx context.Context) error
}

func main() {
	var (
		wg                 = &sync.WaitGroup{}
		ctx                = context.Background()
		services           = make(map[string]service)
		serviceName string = "ui"
	)

	cfg, err := configuration.New(ctx)
	if err != nil {
		panic(err)
	}

	if cfg.UI == nil {
		panic("ui configuration is required but not found in config file")
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

	var eventPublisher apiv1.EventPublisher
	if cfg.Common.Kafka.Enabled {
		var err error
		eventPublisher, err = outbound.New(ctx, cfg, tracer, log)
		services["eventPublisher"] = eventPublisher
		if err != nil {
			panic(err)
		}
	} else {
		mainLog.Info("EventPublisher disabled in config")
	}

	apiClient, err := apiv1.New(ctx, cfg, tracer, eventPublisher, log)
	if err != nil {
		panic(err)
	}

	cacheService, err := cache.New(ctx, cfg, log)
	if err != nil {
		panic(err)
	}
	services["cacheService"] = cacheService

	httpService, err := httpserver.New(ctx, cfg, apiClient, tracer, cacheService, log)
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
			mainLog.Trace("serviceName", serviceName, "error", err)
		}
	}

	if err := tracer.Shutdown(ctx); err != nil {
		mainLog.Error(err, "Tracer shutdown")
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}
