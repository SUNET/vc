package main

import (
	"context"

	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/internal/apigw/httpserver"
	"github.com/SUNET/vc/internal/apigw/samlsp"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

func initSAMLSPService(ctx context.Context, cfg *model.Cfg, cacheService *cache.Service, log *logger.Log) (httpserver.SAMLSPService, error) {
	if !cfg.APIGW.Inbound.SAML.Enable {
		return nil, nil
	}

	samlSPService, err := samlsp.New(ctx, &cfg.APIGW.Inbound.SAML, cacheService.SAMLSession, log)
	if err != nil {
		return nil, err
	}

	log.Info("SAML service initialized", "entity_id", cfg.APIGW.Inbound.SAML.EntityID)
	return samlSPService, nil
}
