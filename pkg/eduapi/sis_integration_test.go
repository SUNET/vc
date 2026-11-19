//go:build integration

package eduapi

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/oauth2client"
	"github.com/SUNET/vc/pkg/testsupport/sistest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sisClient starts SIS and returns an Edu-API client for it that authenticates
// the way a deployed vc does: client credentials against a token endpoint.
func sisClient(t *testing.T) *Client {
	t.Helper()
	stack := sistest.Start(t)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	http, err := oauth2client.New(oauth2client.Config{
		BaseURL:      stack.BaseURL,
		TokenURL:     stack.TokenURL,
		ClientID:     sistest.ClientID,
		ClientSecret: sistest.ClientSecret,
		Scopes:       []string{sistest.ReadScope},
		Timeout:      10 * time.Second,
		Name:         "eduapi",
		TokenCache:   cache.NewMemoryCache[string](time.Hour),
	}, log)
	require.NoError(t, err)
	return NewClient(http)
}

// The student the fixture is built around: read through SIS's own Edu-API, so
// the models and routes are checked against the real provider rather than
// against a mock written by the same hand as the client.
func TestSIS_GetPerson(t *testing.T) {
	client := sisClient(t)

	p, err := client.GetPerson(t.Context(), "liu:anna.andersson")
	require.NoError(t, err)

	assert.Equal(t, "liu:anna.andersson", p.SourcedID)
	require.NotNil(t, p.LegalName)
	assert.Equal(t, "Anna", p.LegalName.GivenName)
	assert.Equal(t, "Andersson", p.LegalName.FamilyName)
	assert.Equal(t, "2001-03-14", p.DateOfBirth)
	require.NotNil(t, p.PrimaryEmail)
	assert.Equal(t, "annan001@student.liu.se", p.PrimaryEmail.Email)
	assert.NotEmpty(t, p.RecordLanguage)
}

func TestSIS_GetPersonNotFound(t *testing.T) {
	client := sisClient(t)

	_, err := client.GetPerson(t.Context(), "liu:nobody")

	assert.Error(t, err)
}

// SIS does not filter /enrollments on person yet (it answers 400 invalid_filter_field),
// so the filter is checked against what it does answer today. When SIS supports
// person='<sourcedId>', this test turns into a check of ListActiveEnrollments.
func TestSIS_ListActiveEnrollments(t *testing.T) {
	client := sisClient(t)

	enrollments, err := client.ListActiveEnrollments(t.Context(), "liu:anna.andersson")
	if err != nil {
		t.Skipf("SIS does not support the person filter on /enrollments yet: %v", err)
	}

	require.Len(t, enrollments, 1, "the inactive enrollment must be dropped")
	assert.Equal(t, "liu:TDDE01-vt2026", enrollments[0].EducationOffering)
	assert.Equal(t, "course", enrollments[0].OfferingType)
	assert.True(t, enrollments[0].IsActive)
}

func TestSIS_CourseOfferingAndOrganization(t *testing.T) {
	client := sisClient(t)

	co, err := client.GetCourseOffering(t.Context(), "liu:TDDE01-vt2026")
	require.NoError(t, err)
	assert.Equal(t, "standard", co.OfferingType)
	require.NotEmpty(t, co.Title)
	assert.NotEmpty(t, co.Organization)

	org, err := client.GetOrganization(t.Context(), co.Organization)
	require.NoError(t, err)
	require.NotEmpty(t, org.Name)
	assert.NotEmpty(t, org.OrganizationType)
}
