//go:build !saml

package main

import (
	"context"
	"vc/internal/apigw/cache"
	"vc/internal/apigw/httpserver"
	"vc/pkg/logger"
	"vc/pkg/model"
)

func initSAMLSPService(ctx context.Context, cfg *model.Cfg, _ *cache.Service, log *logger.Log) (httpserver.SAMLSPService, error) {
	if cfg.APIGW.SAML.Enable {
		log.Info("SAML enabled in config but not compiled in. Rebuild with -tags saml")
	}
	return nil, nil
}
