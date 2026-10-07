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
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/metric"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/pubsub"
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

	dbService, err := db.New(ctx, cfg, tracer, log)
	services["dbService"] = dbService
	if err != nil {
		panic(err)
	}

	cacheService, err := cache.New(ctx, cfg, dbService, tracer, log)
	if err != nil {
		panic(err)
	}

	notifyBus, notifyBusCleanup, err := buildNotifyBus(cfg, log)
	if err != nil {
		panic(err)
	}

	notifyService, err := notify.NewWithBus(ctx, cfg, log, notifyBus)
	services["notifyService"] = notifyService
	if err != nil {
		panic(err)
	}

	apiv1, err := apiv1.New(ctx, dbService, notifyService, cacheService, cfg, tracer, meter, log)
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

	// Stop the background verifier-key warm-up before tearing its store
	// down, or a download finishing a moment later recreates the directory
	// and leaves half a gigabyte of key files behind.
	apiv1.StopVegaPrewarm(ctx)

	// The Vega verifier-key store is a process-wide directory of decompressed
	// circuit artifacts, up to half a gigabyte of them. The OS would reclaim
	// a temp directory eventually; a configured zk_key_cache.dir it would
	// not, and "eventually" is not a promise worth making about that much
	// disk either way.
	if err := mdoc.CloseVegaVerifierKeyStore(ctx); err != nil {
		mainLog.Error(err, "removing the Vega verifier key store")
	}

	// notifyService.Close only tears down its own subscriptions; the bus
	// and the redis.UniversalClient are owned here and must be released
	// after the service that uses them has stopped.
	if notifyBusCleanup != nil {
		if err := notifyBusCleanup(); err != nil {
			mainLog.Error(err, "notify bus cleanup")
		}
	}

	if err := meter.Shutdown(ctx); err != nil {
		mainLog.Error(err, "Meter shutdown")
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}

// buildNotifyBus picks the notify pub/sub backend from HA config. The
// standalone / no-PubSub path returns a MemoryPubSub so operators that
// never touch cfg.Common.HA.PubSub get the same same-process fan-out
// behaviour as before. The returned cleanup closes the bus (and, for
// the RESP backends, the redis.UniversalClient this function
// constructed), both of which NewWithBus/the pubsub package leave to
// the caller.
func buildNotifyBus(cfg *model.Cfg, log *logger.Log) (pubsub.PubSub, func() error, error) {
	if cfg.Common.HA.PubSub == nil || len(cfg.Common.HA.PubSub.Addrs) == 0 {
		bus := pubsub.NewMemoryPubSub()
		return bus, bus.Close, nil
	}
	client, err := pubsub.NewClient(pubsub.ClientConfig{
		Addrs:    cfg.Common.HA.PubSub.Addrs,
		Username: cfg.Common.HA.PubSub.Username,
		Password: cfg.Common.HA.PubSub.Password,
		DB:       cfg.Common.HA.PubSub.DB,
		TLS:      cfg.Common.HA.PubSub.TLS,
	})
	if err != nil {
		return nil, nil, err
	}
	backend := pubsub.ParseBackend(cfg.Common.HA.PubSub.Backend)
	svc := pubsub.New(backend, client, log.New("pubsub"))
	bus, err := svc.NewPubSub("verifier_notify")
	if err != nil {
		if client != nil {
			_ = client.Close()
		}
		return nil, nil, err
	}
	cleanup := func() error {
		busErr := bus.Close()
		var clientErr error
		if client != nil {
			clientErr = client.Close()
		}
		if busErr != nil {
			return busErr
		}
		return clientErr
	}
	return bus, cleanup, nil
}
