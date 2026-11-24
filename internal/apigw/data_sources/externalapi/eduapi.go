package externalapi

import (
	"context"
	"fmt"
	"sync"

	pkgcache "github.com/SUNET/vc/pkg/cache"
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
func NewEduAPI(ctx context.Context, remote model.Remote, scopes map[string]model.ExternalAPIScope, docCache pkgcache.Cache[map[string]*model.CompleteDocument], tokenCache pkgcache.Cache[string], log *logger.Log) (*EduAPI, error) {
	if len(remote.Scopes) == 0 {
		remote.Scopes = []string{eduapi.DefaultScope}
	}
	base, err := newService(remote, scopes, "application/json", "eduapi", docCache, tokenCache, log)
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
// params may carry an education offering to issue for; it is matched whatever
// the enrollment's status. Without one, the person's first active course
// enrollment is used.
func (s *EduAPI) FetchAndStoreForVCI(ctx context.Context, personID, credentialType, vciSessionID string, params *pkgcache.ExternalAPIParams) error {
	offeringID := ""
	if params != nil && params.EduAPI != nil {
		offeringID = params.EduAPI.EducationOfferingID
	}

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
		if offeringID != "" {
			enrollments, enrollErr = s.client.ListEnrollments(fetchCtx, personID)
		} else {
			enrollments, enrollErr = s.client.ListActiveEnrollments(fetchCtx, personID)
		}
	}()
	wg.Wait()

	if personErr != nil {
		return personFetchError("eduapi", personID, personErr)
	}

	// Flatten person data
	claims := person.Flatten()

	// Merge the chosen enrollment and its course offering / organisation.
	switch {
	case enrollErr != nil && offeringID != "":
		return fmt.Errorf("eduapi: list enrollments for %s: %w", personID, enrollErr)
	case enrollErr != nil:
		s.log.Info("Could not fetch enrollments, continuing without", "error", enrollErr)
	default:
		if err := s.mergeEnrollmentClaims(ctx, claims, enrollments, offeringID); err != nil {
			return err
		}
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

// mergeEnrollmentClaims flattens the enrollment in offeringID, or the first
// course enrollment when offeringID is empty, and, best-effort, its course
// offering and the offering's organisation into claims. Missing references and
// failed lookups are logged and skipped. A requested offering the person has no
// enrollment in, in any status, is an error: no other course is substituted.
func (s *EduAPI) mergeEnrollmentClaims(ctx context.Context, claims map[string]any, enrollments []eduapi.Enrollment, offeringID string) error {
	if offeringID != "" {
		e := enrollmentInOffering(enrollments, offeringID)
		if e == nil {
			return ErrNotEnrolled
		}
		s.mergeEnrollment(ctx, claims, e)
		return nil
	}

	if e := firstCourseEnrollment(enrollments); e != nil {
		s.mergeEnrollment(ctx, claims, e)
	}
	return nil
}

// mergeEnrollment flattens one enrollment and, best-effort, its course offering
// and the offering's organisation into claims.
func (s *EduAPI) mergeEnrollment(ctx context.Context, claims map[string]any, e *eduapi.Enrollment) {
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

// enrollmentInOffering returns the enrollment in the given education offering,
// preferring an active one when the person has several, or nil.
func enrollmentInOffering(enrollments []eduapi.Enrollment, offeringID string) *eduapi.Enrollment {
	var found *eduapi.Enrollment
	for i := range enrollments {
		if enrollments[i].EducationOffering != offeringID {
			continue
		}
		if enrollments[i].IsActive {
			return &enrollments[i]
		}
		if found == nil {
			found = &enrollments[i]
		}
	}
	return found
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
