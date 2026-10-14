package externalapi

import (
	"context"
	"fmt"
	"sync"

	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oeapi"
)

// OEAPI is the Open Education API (OEAPI v6.0) data source: it fetches a
// person's educational data from an OEAPI-compliant endpoint and transforms it
// into credential claims for OpenID4VCI issuance.
type OEAPI struct {
	*service
	client *oeapi.Client
	log    *logger.Log
}

// NewOEAPI creates an OEAPI data source from a remote connection definition and
// the external_api scopes that reference it. Each scope's AttributeMapping is
// wired into a per-credential-type mapper.
func NewOEAPI(ctx context.Context, remote model.Remote, scopes map[string]model.ExternalAPIScope, docCache pkgcache.Cache[map[string]*model.CompleteDocument], tokenCache pkgcache.Cache[string], log *logger.Log) (*OEAPI, error) {
	base, err := newService(remote, scopes, "application/vnd.oeapi+json, application/json", "oeapi", docCache, tokenCache, log)
	if err != nil {
		return nil, err
	}

	svcLog := log.New("oeapi")
	svcLog.Info("OEAPI service initialized", "base_url", remote.BaseURL)
	return &OEAPI{service: base, client: oeapi.NewClient(base.http), log: svcLog}, nil
}

// FetchAndStoreForVCI queries the OEAPI for a person's educational data,
// transforms it using the configured credential mappings, and stores the
// resulting document in the VCI session cache.
//
// personID is the OEAPI personId that identifies the student.
// credentialType is the credential type being issued.
// vciSessionID is the OpenID4VCI session to associate the document with.
func (s *OEAPI) FetchAndStoreForVCI(ctx context.Context, personID, credentialType, vciSessionID string) error {
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
		// The programme-offering-associations collection does not support expand;
		// the selected association is enriched via its instance endpoint below.
		programmeAssociations, programmeErr = s.client.GetProgrammeOfferingAssociationsForPerson(fetchCtx, personID)
	}()
	go func() {
		defer wg.Done()
		courseAssociations, courseErr = s.client.GetCourseOfferingAssociationsForPerson(fetchCtx, personID, oeapi.WithExpand("course_offering"))
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
		// The collection omits the programme offering, so pull the selected
		// association from the instance endpoint (which supports expand).
		if a.ProgrammeOffering == nil && a.AssociationID != "" {
			if full, err := s.client.GetProgrammeOfferingAssociation(ctx, a.AssociationID, oeapi.WithExpand("programme_offering")); err != nil {
				s.log.Info("Could not expand programme offering association, continuing without", "association_id", a.AssociationID, "error", err)
			} else {
				a = full
			}
		}
		mergeClaims(claims, "programme.", a.Flatten())
	}

	// Merge first active course association and its embedded result.
	if courseErr != nil {
		s.log.Info("Could not fetch course offering associations, continuing without", "error", courseErr)
	} else if a := firstActiveCourseAssociation(courseAssociations); a != nil {
		mergeClaims(claims, "course.", a.Flatten())
	}

	// Apply the configured mapper and store the resulting VCI document.
	count, err := s.storeMappedDocument(ctx, credentialType, vciSessionID, claims)
	if err != nil {
		return fmt.Errorf("oeapi: transform claims: %w", err)
	}

	s.log.Info("OEAPI document stored for VCI",
		"vci_session_id", vciSessionID,
		"credential_type", credentialType,
		"claims_count", count)

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
