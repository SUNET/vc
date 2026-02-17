//go:build !oidcrp

package main

import (
	"context"
	"vc/internal/apigw/cache"
	"vc/internal/apigw/db"
	"vc/internal/apigw/httpserver"
	"vc/pkg/logger"
	"vc/pkg/model"
)

func initOIDCRPService(ctx context.Context, cfg *model.Cfg, _ *cache.Service, dbService *db.Service, log *logger.Log) (httpserver.OIDCRPService, error) {
	if cfg.APIGW.OIDCRP.Enable {
		log.Info("OIDC RP enabled in config but not compiled in. Rebuild with -tags oidcrp")
	}
	return nil, nil
}
