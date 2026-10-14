// Package externalapi implements the external-API credential data sources
// (eduapi, oeapi) for the API Gateway: each fetches a person's data from an
// OAuth2-protected API and transforms it into OpenID4VCI credential claims.
package externalapi

import (
	"context"
	"fmt"

	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2client"
)

// service is the shared base for the external-API data sources: it owns the
// authenticated HTTP client, the per-credential-type attribute mappers, the
// authentic source and the document cache. Each concrete source embeds it.
type service struct {
	http            *oauth2client.Client
	mappers         map[string]*credential.AttributeMapper
	authenticSource string
	docCache        pkgcache.Cache[map[string]*model.CompleteDocument]
}

// newService builds the shared base for a remote: an OAuth2 client-credentials
// HTTP client, per-credential-type mappers from the external_api scopes, the
// authentic source and the document cache. accept is the Accept header and name
// scopes the client's logging/errors (e.g. "oeapi").
func newService(remote model.Remote, scopes map[string]model.ExternalAPIScope, accept, name string, docCache pkgcache.Cache[map[string]*model.CompleteDocument], tokenCache pkgcache.Cache[string], log *logger.Log) (*service, error) {
	httpClient, err := oauth2client.New(oauth2client.Config{
		BaseURL:      remote.BaseURL,
		TokenURL:     remote.TokenURL,
		ClientID:     remote.ClientID,
		ClientSecret: remote.ClientSecret,
		Scopes:       remote.Scopes,
		Timeout:      remote.Timeout,
		Accept:       accept,
		Name:         name,
		TokenCache:   tokenCache,
	}, log)
	if err != nil {
		return nil, fmt.Errorf("%s: create client: %w", name, err)
	}

	mappers := make(map[string]*credential.AttributeMapper, len(scopes))
	for credType, scope := range scopes {
		mappers[credType] = credential.NewAttributeMapper(scope.AttributeMapping)
	}

	return &service{
		http:            httpClient,
		mappers:         mappers,
		authenticSource: remote.BaseURL,
		docCache:        docCache,
	}, nil
}

// storeMappedDocument applies the mapper for credentialType (if any) to claims,
// wraps the result in a CompleteDocument keyed by the authentic source, stores
// it in the VCI session cache, and returns the number of stored claims.
func (s *service) storeMappedDocument(ctx context.Context, credentialType, vciSessionID string, claims map[string]any) (int, error) {
	transformed := claims
	if m, ok := s.mappers[credentialType]; ok {
		var err error
		transformed, err = m.Apply(claims)
		if err != nil {
			return 0, err
		}
	}

	doc := &model.CompleteDocument{
		Meta:         &model.MetaData{AuthenticSource: s.authenticSource},
		DocumentData: transformed,
	}
	s.docCache.Set(ctx, vciSessionID, map[string]*model.CompleteDocument{s.authenticSource: doc})
	return len(transformed), nil
}

// mergeClaims copies src into dst, prefixing each key.
func mergeClaims(dst map[string]any, prefix string, src map[string]any) {
	for k, v := range src {
		dst[prefix+k] = v
	}
}
