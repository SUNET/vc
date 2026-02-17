//go:build saml

package main

import (
	"context"
	"vc/internal/apigw/cache"
	"vc/internal/apigw/httpserver"
	"vc/internal/apigw/samlsp"
	"vc/pkg/logger"
	"vc/pkg/model"
)

func initSAMLSPService(ctx context.Context, cfg *model.Cfg, cacheService *cache.Service, log *logger.Log) (httpserver.SAMLSPService, error) {
	if !cfg.APIGW.SAML.Enabled {
		return nil, nil
	}

	samlSPService, err := samlsp.New(ctx, &cfg.APIGW.SAML, cacheService.SAMLSession, log)
	if err != nil {
		return nil, err
	}

	log.Info("SAML service initialized", "entity_id", cfg.APIGW.SAML.EntityID)
	return samlSPService, nil
}
