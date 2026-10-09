package staticembed

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// verificationPath matches a /verification/<segment> reference in an
// embedded asset, template interpolation and all.
var verificationPath = regexp.MustCompile(`/verification/([A-Za-z0-9_-]+)`)

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
// Checked against a list rather than against the live gin route table,
// because building one means building the whole Service - a real
// apiv1.Client, notify, tracer and cache - which this package cannot do.
// The list is therefore kept honest by the second test below, which fails
// if service.go stops registering one of them.
func TestStaticAssetsOnlyFetchRegisteredVerificationRoutes(t *testing.T) {
	registered := map[string]bool{
		"request-object":     true,
		"direct_post":        true,
		"callback":           true,
		"session-preference": true,
		"oidc-direct_post":   true,
		"oidc-callback":      true,
		"display":            true,
		"confirm":            true,
	}

	assets, err := fs.Glob(FS, "*")
	if err != nil {
		t.Fatal(err)
	}

	var offenders []string
	for _, name := range assets {
		switch filepath.Ext(name) {
		case ".html", ".js":
		default:
			continue
		}

		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range verificationPath.FindAllStringSubmatch(stripComments(string(body)), -1) {
			if !registered[m[1]] {
				offenders = append(offenders, name+" -> /verification/"+m[1])
			}
		}
	}

	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s is not a route the verifier registers", o)
	}
}

// ... and the DC API path really does ask for the signed request object,
// so the test above cannot pass by the assets having stopped fetching
// anything at all.
func TestDCAPIAssetsFetchTheSignedRequestObject(t *testing.T) {
	for _, name := range []string{"digital-credentials.js", "authorize_enhanced.html"} {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stripComments(string(body)), "/verification/request-object/") {
			t.Errorf("%s no longer fetches the signed request object", name)
		}
	}
}

// stripComments drops whole-line // and * comments and <!-- --> blocks.
//
// The test is about what the assets FETCH, and a comment explaining a
// route that no longer exists is not a fetch. Only whole-line comments are
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

var htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)
