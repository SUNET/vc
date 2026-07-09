package main

import (
	"context"
	"encoding/gob"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/SUNET/vc/internal/verifier/apiv1"
	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/internal/verifier/httpserver"
	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/metric"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"
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
		serviceName string = "verifier"
	)

	cfg, err := configuration.New(ctx, serviceName)
	if err != nil {
		panic(err)
	}

	if cfg.Verifier == nil {
		panic("verifier configuration is required but not found in config file")
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

	meter, err := metric.New(ctx, cfg, serviceName, log)
	if err != nil {
		panic(err)
	}
	vpMetrics, err := metric.NewVP(meter.Meter)
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

	notifyService, err := notify.New(ctx, cfg, log)
	services["notifyService"] = notifyService
	if err != nil {
		panic(err)
	}

	apiv1, err := apiv1.New(ctx, dbService, notifyService, cacheService, cfg, tracer, vpMetrics, log)
	if err != nil {
		panic(err)
	}

	httpserver, err := httpserver.New(ctx, cfg, apiv1, notifyService, tracer, cacheService, log)
	services["httpserver"] = httpserver
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

	if err := meter.Shutdown(ctx); err != nil {
		mainLog.Error(err, "Meter shutdown")
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}
