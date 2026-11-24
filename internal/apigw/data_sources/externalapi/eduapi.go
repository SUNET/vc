package externalapi

import (
	"context"
	"fmt"
	"sync"

	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/eduapi"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

// EduAPI is the 1EdTech Edu-API data source: it fetches student data from an
// Edu-API compliant SIS (e.g. Ladok) and transforms it into credential claims
// for OpenID4VCI issuance.
type EduAPI struct {
	*service
	client *eduapi.Client
	log    *logger.Log
}

// NewEduAPI creates an Edu-API data source from a remote connection definition
// and the external_api scopes that reference it. Each scope's AttributeMapping
// is wired into a per-credential-type mapper.
func NewEduAPI(ctx context.Context, remote model.Remote, scopes map[string]model.ExternalAPIScope, documentShape func(scope string) (claimpath.Shape, error), docCache pkgcache.Cache[map[string]*model.CompleteDocument], tokenCache pkgcache.Cache[string], log *logger.Log) (*EduAPI, error) {
	if len(remote.Scopes) == 0 {
		remote.Scopes = []string{eduapi.DefaultScope}
	}
	base, err := newService(remote, scopes, documentShape, "application/json", "eduapi", docCache, tokenCache, log)
	if err != nil {
		return nil, err
	}

	svcLog := log.New("eduapi")
	svcLog.Info("Edu-API service initialized", "base_url", remote.BaseURL)
	return &EduAPI{service: base, client: eduapi.NewClient(base.http), log: svcLog}, nil
}

// FetchAndStoreForVCI queries the Edu-API for a person's education data,
// transforms it using the configured credential mappings, and stores the
// resulting document in the VCI session cache.
//
// personID is the Edu-API sourcedId that identifies the student.
// credentialType is the credential type being issued (e.g. "EuropeanStudentID").
// vciSessionID is the OpenID4VCI session to associate the document with.
func (s *EduAPI) FetchAndStoreForVCI(ctx context.Context, personID, credentialType, vciSessionID string) error {
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
		enrollments, enrollErr = s.client.ListActiveEnrollments(fetchCtx, personID)
	}()
	wg.Wait()

	if personErr != nil {
		return fmt.Errorf("eduapi: fetch person %s: %w", personID, personErr)
	}

	// Flatten person data
	claims := person.Flatten()

	// Merge the first active enrollment and its course offering / organisation.
	if enrollErr != nil {
		s.log.Info("Could not fetch enrollments, continuing without", "error", enrollErr)
	} else {
		s.mergeEnrollmentClaims(ctx, claims, enrollments)
	}

	// Apply the configured mapper and store the resulting VCI document.
	count, err := s.storeMappedDocument(ctx, credentialType, vciSessionID, claims)
	if err != nil {
		return fmt.Errorf("eduapi: transform claims: %w", err)
	}

	s.log.Info("Edu-API document stored for VCI",
		"vci_session_id", vciSessionID,
		"credential_type", credentialType,
		"claims_count", count)

	return nil
}

// mergeEnrollmentClaims flattens the first course enrollment and, best-effort,
// its course offering and the offering's organisation into claims. Missing
// references and failed lookups are logged and skipped, not treated as errors.
func (s *EduAPI) mergeEnrollmentClaims(ctx context.Context, claims map[string]any, enrollments []eduapi.Enrollment) {
	e := firstCourseEnrollment(enrollments)
	if e == nil {
		return
	}
	mergeClaims(claims, "enrollment.", e.Flatten())

	course, err := s.client.GetCourseOffering(ctx, e.EducationOffering)
	if err != nil {
		s.log.Info("Could not fetch course offering", "offering_id", e.EducationOffering, "error", err)
		return
	}
	mergeClaims(claims, "course.", course.Flatten())

	if course.Organization == "" {
		return
	}
	org, err := s.client.GetOrganization(ctx, course.Organization)
	if err != nil {
		s.log.Info("Could not fetch organization", "org_id", course.Organization, "error", err)
		return
	}
	mergeClaims(claims, "organization.", org.Flatten())
}

// firstCourseEnrollment returns the first enrollment in a course offering, or nil.
func firstCourseEnrollment(enrollments []eduapi.Enrollment) *eduapi.Enrollment {
	for i := range enrollments {
		if enrollments[i].OfferingType == "course" {
			return &enrollments[i]
		}
	}
	return nil
}
