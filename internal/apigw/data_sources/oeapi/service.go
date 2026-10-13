// Package oeapi implements the Open Education API (OEAPI) integration service for
// the API Gateway. It fetches a person's educational data from an OEAPI v6.0
// compliant endpoint and transforms it into credential claims for OpenID4VCI issuance.
package oeapi

import (
	"context"
	"fmt"
	"sync"

	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oeapi"
)

// Service is the OEAPI integration service for the API Gateway.
type Service struct {
	cfg      *oeapi.Config
	client   *oeapi.Client
	mappers  map[string]*credential.AttributeMapper // credential type → mapper
	docCache pkgcache.Cache[map[string]*model.CompleteDocument]
	log      *logger.Log
}

// New creates a new OEAPI service from a remote connection definition.
func New(ctx context.Context, remote model.Remote, docCache pkgcache.Cache[map[string]*model.CompleteDocument], tokenCache pkgcache.Cache[string], log *logger.Log) (*Service, error) {
	cfg := &oeapi.Config{
		Enable:       true,
		BaseURL:      remote.BaseURL,
		TokenURL:     remote.TokenURL,
		ClientID:     remote.ClientID,
		ClientSecret: remote.ClientSecret,
		Scopes:       remote.Scopes,
		Timeout:      remote.Timeout,
	}

	clientCfg := cfg.ClientConfig()
	clientCfg.TokenCache = tokenCache

	client, err := oeapi.NewClient(clientCfg, log)
	if err != nil {
		return nil, fmt.Errorf("oeapi: create client: %w", err)
	}

	mappers := make(map[string]*credential.AttributeMapper, len(cfg.AttributeMappings))
	for credType, mapping := range cfg.AttributeMappings {
		mappers[credType] = credential.NewAttributeMapper(toModelMapping(mapping))
	}

	s := &Service{
		cfg:      cfg,
		client:   client,
		mappers:  mappers,
		docCache: docCache,
		log:      log.New("oeapi"),
	}

	log.Info("OEAPI service initialized", "base_url", cfg.BaseURL)
	return s, nil
}

// FetchAndStoreForVCI queries the OEAPI for a person's educational data,
// transforms it using the configured credential mappings, and stores the
// resulting document in the VCI session cache.
//
// personID is the OEAPI personId that identifies the student.
// credentialType is the credential type being issued.
// vciSessionID is the OpenID4VCI session to associate the document with.
func (s *Service) FetchAndStoreForVCI(ctx context.Context, personID, credentialType, vciSessionID string) error {
	s.log.Info("Fetching OEAPI data for VCI",
		"person_id", personID,
		"credential_type", credentialType,
		"vci_session_id", vciSessionID)

	// Fetch person, programme associations and course associations in parallel —
	// they are independent calls. Use a derived context so that if GetPerson fails
	// quickly we can cancel the (potentially slow) association requests.
	var (
		person                *oeapi.Person
		programmeAssociations []oeapi.ProgrammeOfferingAssociation
		courseAssociations    []oeapi.CourseOfferingAssociation
		personErr             error
		programmeErr          error
		courseErr             error
		wg                    sync.WaitGroup
	)

	fetchCtx, fetchCancel := context.WithCancel(ctx)
	defer fetchCancel()

	wg.Add(3)
	go func() {
		defer wg.Done()
		person, personErr = s.client.GetPerson(fetchCtx, personID)
		if personErr != nil {
			fetchCancel()
		}
	}()
	go func() {
		defer wg.Done()
		programmeAssociations, programmeErr = s.client.GetProgrammeOfferingAssociationsForPerson(fetchCtx, personID)
	}()
	go func() {
		defer wg.Done()
		courseAssociations, courseErr = s.client.GetCourseOfferingAssociationsForPerson(fetchCtx, personID)
	}()
	wg.Wait()

	if personErr != nil {
		return fmt.Errorf("oeapi: fetch person %s: %w", personID, personErr)
	}

	claims := person.Flatten()

	// Merge first active programme association and its embedded result.
	if programmeErr != nil {
		s.log.Info("Could not fetch programme offering associations, continuing without", "error", programmeErr)
	} else if a := firstActiveProgrammeAssociation(programmeAssociations); a != nil {
		for k, v := range a.Flatten() {
			claims["programme."+k] = v
		}
	}

	// Merge first active course association and its embedded result.
	if courseErr != nil {
		s.log.Info("Could not fetch course offering associations, continuing without", "error", courseErr)
	} else if a := firstActiveCourseAssociation(courseAssociations); a != nil {
		for k, v := range a.Flatten() {
			claims["course."+k] = v
		}
	}

	// Apply attribute mapper if configured for this credential type.
	var transformedClaims map[string]any
	if t, ok := s.mappers[credentialType]; ok {
		var err error
		transformedClaims, err = t.Apply(claims)
		if err != nil {
			return fmt.Errorf("oeapi: transform claims: %w", err)
		}
	} else {
		transformedClaims = claims
	}

	doc := &model.CompleteDocument{
		Meta: &model.MetaData{
			AuthenticSource: s.cfg.BaseURL,
		},
		DocumentData: transformedClaims,
	}
	docs := map[string]*model.CompleteDocument{
		s.cfg.BaseURL: doc,
	}

	s.docCache.Set(ctx, vciSessionID, docs)

	s.log.Info("OEAPI document stored for VCI",
		"vci_session_id", vciSessionID,
		"credential_type", credentialType,
		"claims_count", len(transformedClaims))

	return nil
}

// firstActiveProgrammeAssociation returns the first "associated" programme
// association, or the first association if none are active, or nil if empty.
func firstActiveProgrammeAssociation(associations []oeapi.ProgrammeOfferingAssociation) *oeapi.ProgrammeOfferingAssociation {
	if len(associations) == 0 {
		return nil
	}
	for i := range associations {
		if associations[i].State == "associated" {
			return &associations[i]
		}
	}
	return &associations[0]
}

// firstActiveCourseAssociation returns the first "associated" course association,
// or the first association if none are active, or nil if empty.
func firstActiveCourseAssociation(associations []oeapi.CourseOfferingAssociation) *oeapi.CourseOfferingAssociation {
	if len(associations) == 0 {
		return nil
	}
	for i := range associations {
		if associations[i].State == "associated" {
			return &associations[i]
		}
	}
	return &associations[0]
}

// GetCredentialTypes returns the list of credential types this service handles.
func (s *Service) GetCredentialTypes() []string {
	return s.cfg.CredentialTypes
}

// toModelMapping converts oeapi.AttributeMapping to model.AttributeMapping.
// The types are structurally identical but defined separately to avoid
// a circular import between pkg/oeapi and pkg/model.
func toModelMapping(src oeapi.AttributeMapping) model.AttributeMapping {
	attrs := make(model.AttributeMapping, len(src))
	for ak, av := range src {
		attrs[ak] = model.AttributeConfig{
			Claim:    av.Claim,
			Required: av.Required,
			Default:  av.Default,
		}
	}
	return attrs
}
