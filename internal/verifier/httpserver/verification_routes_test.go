package httpserver

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/verifier/staticembed"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verificationPath matches a /verification/<segment> reference in an
// embedded asset, template interpolation and all.
var verificationPath = regexp.MustCompile(`/verification/([A-Za-z0-9_-]+)`)

// htmlComment matches an HTML comment block.
var htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

// The browser assets must only fetch verification routes the verifier
// actually registers.
//
// The Digital Credentials API button fetched /verification/request/{session}
// whenever use_jar was false - which was the DEFAULT - and no such route
// has ever existed. The verifier registers request-object and
// request-object/:session_id and nothing else, both serving a signed JWT,
// so the default configuration produced "Failed to fetch authorization
// request: 404" and only the non-default value worked (SUNET/vc#755).
//
// The allowlist comes from verificationRouteNames, which is derived from
// the tables New() registers from - so renaming or removing a route moves
// the allowlist with it and this test fails while an asset still fetches
// the old name. That is why the test lives here and not in staticembed,
// which cannot see the registrations.
func TestStaticAssetsOnlyFetchRegisteredVerificationRoutes(t *testing.T) {
	registered := verificationRouteNames()
	require.NotEmpty(t, registered, "no verification routes found - the tables are not being read")

	assets, err := fs.Glob(staticembed.FS, "*")
	require.NoError(t, err)

	var scanned int
	var offenders []string
	for _, name := range assets {
		switch filepath.Ext(name) {
		case ".html", ".js":
		default:
			continue
		}
		scanned++

		body, err := staticembed.FS.ReadFile(name)
		require.NoError(t, err)

		for _, m := range verificationPath.FindAllStringSubmatch(stripComments(string(body)), -1) {
			if !registered[m[1]] {
				offenders = append(offenders, name+" -> /verification/"+m[1])
			}
		}
	}

	require.NotZero(t, scanned, "no embedded .html/.js assets were scanned")

	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s is not a route the verifier registers", o)
	}
}

// ... and the DC API path really does ask for the signed request object, so
// the test above cannot pass by the assets having stopped fetching anything
// at all. The route name comes from the same table, so this also fails if
// the endpoint is renamed without the assets following.
func TestDCAPIAssetsFetchTheSignedRequestObject(t *testing.T) {
	var requestObject string
	for _, r := range oidcVerificationRoutes {
		if strings.HasPrefix(r.path, "request-object") {
			requestObject = r.name()
		}
	}
	require.NotEmpty(t, requestObject, "the OIDC request-object route is no longer registered")

	want := "/verification/" + requestObject + "/"
	for _, name := range []string{"digital-credentials.js", "authorize_enhanced.html"} {
		body, err := staticembed.FS.ReadFile(name)
		require.NoError(t, err)

		assert.Contains(t, stripComments(string(body)), want,
			"%s no longer fetches the signed request object", name)
	}
}

// stripComments drops whole-line // and * comments and <!-- --> blocks.
//
// The test is about what the assets FETCH, and a comment explaining a route
// that no longer exists is not a fetch. Only whole-line comments are
// removed, so a "//" inside a URL in real code is left alone.
func stripComments(body string) string {
	body = htmlComment.ReplaceAllString(body, "")

	var kept []string
	for line := range strings.SplitSeq(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}
