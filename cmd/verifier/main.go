package main

import (
	"context"
	"encoding/gob"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"vc/internal/verifier/apiv1"
	"vc/internal/verifier/cache"
	"vc/internal/verifier/db"
	"vc/internal/verifier/httpserver"
	"vc/internal/verifier/notify"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"flag"
	"vc/internal/verifier/zk"
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
		certs      = flag.String("cacerts", "/app/vc/internal/verifier/zk/certs.pem", "File containing issuer CA certs")
		circuitDir         = flag.String("circuit_dir", "/app/vc/internal/verifier/zk/circuits", "Directory from which to load circuits")
	)

	flag.Parse()
	zk.LoadCircuits(*circuitDir)

	pem, err := os.ReadFile(*certs)
	if err != nil {
		panic("could not parse cacerts file")
		os.Exit(1)
	}
	if err := zk.LoadIssuerRootCA(pem); err != nil {
		panic("could not load issuer root CA")
		os.Exit(1)
	}

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

	apiv1, err := apiv1.New(ctx, dbService, notifyService, cacheService, cfg, tracer, log)
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

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}
