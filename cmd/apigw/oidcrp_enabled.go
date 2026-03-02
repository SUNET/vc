//go:build oidcrp

package main

import (
	"context"

	"vc/internal/apigw/cache"
	"vc/internal/apigw/db"
	"vc/internal/apigw/httpserver"
	"vc/internal/apigw/oidcrp"
	"vc/pkg/logger"
	"vc/pkg/model"
)

func initOIDCRPService(ctx context.Context, cfg *model.Cfg, cacheService *cache.Service, dbService *db.Service, log *logger.Log) (httpserver.OIDCRPService, error) {
	if !cfg.APIGW.OIDCRP.Enable {
		return nil, nil
	}

	oidcrpService, err := oidcrp.New(ctx, &cfg.APIGW.OIDCRP, cacheService.OIDCRPSession, dbService, log)
	if err != nil {
		return nil, err
	}

	log.Info("OIDC RP service initialized", "issuer_url", cfg.APIGW.OIDCRP.IssuerURL)
	return oidcrpService, nil
}
