// Package eduapi implements the Edu-API integration service for the API Gateway.
// It fetches student data from a 1EdTech Edu-API compliant SIS (e.g. Ladok)
// and transforms it into credential claims for OpenID4VCI issuance.
package eduapi

import (
	"context"
	"fmt"
	"sync"

	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/eduapi"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

// Service is the Edu-API integration service for the API Gateway.
type Service struct {
	cfg          *eduapi.Config
	client       *eduapi.Client
	transformers map[string]*credential.ClaimTransformer // credential type → transformer
	docCache     pkgcache.Cache[map[string]*model.CompleteDocument]
	log          *logger.Log
}

// New creates a new Edu-API service.
func New(ctx context.Context, cfg *eduapi.Config, docCache pkgcache.Cache[map[string]*model.CompleteDocument], tokenCache pkgcache.Cache[string], log *logger.Log) (*Service, error) {
	if !cfg.Enable {
		log.Info("Edu-API support disabled")
		return nil, nil
	}

	clientCfg := cfg.ClientConfig()
	clientCfg.TokenCache = tokenCache

	client, err := eduapi.NewClient(clientCfg, log)
	if err != nil {
		return nil, fmt.Errorf("eduapi: create client: %w", err)
	}

	transformers := make(map[string]*credential.ClaimTransformer, len(cfg.AttributeMappings))
	for credType, mapping := range cfg.AttributeMappings {
		transformers[credType] = credential.NewClaimTransformer(toModelMapping(mapping))
	}

	s := &Service{
		cfg:          cfg,
		client:       client,
		transformers: transformers,
		docCache:     docCache,
		log:          log.New("eduapi"),
	}

	log.Info("Edu-API service initialized", "base_url", cfg.BaseURL)
	return s, nil
}

// FetchAndStoreForVCI queries the Edu-API for a person's education data,
// transforms it using the configured credential mappings, and stores the
// resulting document in the VCI session cache.
//
// personID is the Edu-API sourcedId that identifies the student.
// credentialType is the credential type being issued (e.g. "EuropeanStudentID").
// vciSessionID is the OpenID4VCI session to associate the document with.
func (s *Service) FetchAndStoreForVCI(ctx context.Context, personID, credentialType, vciSessionID string) error {
	s.log.Info("Fetching Edu-API data for VCI",
		"person_id", personID,
		"credential_type", credentialType,
		"vci_session_id", vciSessionID)

	// Fetch person and enrollments in parallel — they are independent calls.
	// Use a derived context so that if GetPerson fails quickly we can cancel
	// the (potentially slow) enrollments request instead of blocking on it.
	var (
		person      *eduapi.Person
		enrollments []eduapi.Enrollment
		personErr   error
		enrollErr   error
		wg          sync.WaitGroup
	)

	fetchCtx, fetchCancel := context.WithCancel(ctx)
	defer fetchCancel()

	wg.Add(2)
	go func() {
		defer wg.Done()
		person, personErr = s.client.GetPerson(fetchCtx, personID)
		if personErr != nil {
			fetchCancel()
		}
	}()
	go func() {
		defer wg.Done()
		enrollments, enrollErr = s.client.GetEnrollmentsForPerson(fetchCtx, personID)
	}()
	wg.Wait()

	if personErr != nil {
		return fmt.Errorf("eduapi: fetch person %s: %w", personID, personErr)
	}

	// Flatten person data
	claims := person.Flatten()

	// Merge enrollments
	if enrollErr != nil {
		s.log.Info("Could not fetch enrollments, continuing without", "error", enrollErr)
	} else if len(enrollments) > 0 {
		// Flatten first active enrollment and its course offering
		for _, e := range enrollments {
			if e.Status == "active" {
				enrollmentClaims := e.Flatten()
				for k, v := range enrollmentClaims {
					claims["enrollment."+k] = v
				}

				// Fetch the associated course offering
				if e.ClassRef.SourcedID != "" {
					course, err := s.client.GetCourseOffering(ctx, e.ClassRef.SourcedID)
					if err != nil {
						s.log.Info("Could not fetch course offering", "class_id", e.ClassRef.SourcedID, "error", err)
					} else {
						courseClaims := course.Flatten()
						for k, v := range courseClaims {
							claims["course."+k] = v
						}

						// Fetch the organization (school)
						if course.SchoolRef.SourcedID != "" {
							org, err := s.client.GetOrganization(ctx, course.SchoolRef.SourcedID)
							if err != nil {
								s.log.Info("Could not fetch organization", "org_id", course.SchoolRef.SourcedID, "error", err)
							} else {
								orgClaims := org.Flatten()
								for k, v := range orgClaims {
									claims["organization."+k] = v
								}
							}
						}
					}
				}
				break // Use first active enrollment
			}
		}
	}

	// Apply claim transformer if configured for this credential type
	var transformedClaims map[string]any
	if t, ok := s.transformers[credentialType]; ok {
		var err error
		transformedClaims, err = t.TransformClaims(claims)
		if err != nil {
			return fmt.Errorf("eduapi: transform claims: %w", err)
		}
	} else {
		transformedClaims = claims
	}

	// Store as VCI document
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

	s.log.Info("Edu-API document stored for VCI",
		"vci_session_id", vciSessionID,
		"credential_type", credentialType,
		"claims_count", len(transformedClaims))

	return nil
}

// GetCredentialTypes returns the list of credential types this service handles.
func (s *Service) GetCredentialTypes() []string {
	return s.cfg.CredentialTypes
}

// toModelMapping converts eduapi.AttributeMapping to model.AttributeMapping.
// The types are structurally identical but defined separately to avoid
// a circular import between pkg/eduapi and pkg/model.
func toModelMapping(src eduapi.AttributeMapping) model.AttributeMapping {
	attrs := make(model.AttributeMapping, len(src))
	for ak, av := range src {
		attrs[ak] = model.AttributeConfig{
			Claim:     av.Claim,
			Required:  av.Required,
			Transform: av.Transform,
			Default:   av.Default,
		}
	}
	return attrs
}
