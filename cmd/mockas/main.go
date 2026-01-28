package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vc/internal/mockas/apiv1"
	"vc/internal/mockas/bootstrapper"
	"vc/internal/mockas/httpserver"
	"vc/internal/mockas/inbound"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

type service interface {
	Close(ctx context.Context) error
}

func main() {
	var (
		wg                 = &sync.WaitGroup{}
		ctx                = context.Background()
		services           = make(map[string]service)
		serviceName string = "mockas"
	)

	cfg, err := configuration.New(ctx)
	if err != nil {
		panic(err)
	}

	if cfg.MockAS == nil {
		panic("mock_as configuration is required but not found in config file")
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

	//eduClient, err := education.New(ctx, cfg.MockAS.DatastoreURL, log.New("education"))
	//services["eduClient"] = eduClient
	//if err != nil {
	//	panic(err)
	//}

	_, err = bootstrapper.New(ctx, cfg, log)
	if err != nil {
		panic(err)
	}

	apiv1Client, err := apiv1.New(ctx, cfg, tracer, log)
	if err != nil {
		panic(err)
	}

	httpService, err := httpserver.New(ctx, cfg, apiv1Client, tracer, log)
	services["httpService"] = httpService
	if err != nil {
		panic(err)
	}

	if cfg.Common.Kafka.Enabled {
		eventConsumer, err := inbound.New(ctx, cfg, apiv1Client, tracer, log.New("eventConsumer"))
		services["eventConsumer"] = eventConsumer
		if err != nil {
			panic(err)
		}
	} else {
		mainLog.Info("EventPublisher disabled in config")
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
