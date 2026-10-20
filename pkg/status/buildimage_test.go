package status

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The builder images must not be older than go.mod requires.
//
// dockerfiles/worker sets GOTOOLCHAIN=local, which FORBIDS the automatic
// toolchain upgrade - that is deliberate, so a release links the
// toolchain the image ships rather than whatever go.dev serves that day.
// The cost is that an image older than go.mod's `go` directive does not
// degrade: the build stops with "go.mod requires go >= 1.27.2 (running
// go 1.27.1)".
//
// This has already happened once. A dependency bump moved go.mod to
// 1.27.2 and updated the workflows, and the two Dockerfiles kept
// golang:1.27.1-bookworm. Nothing in CI noticed, because the test
// workflow uses go-version-file and never builds an image - so the
// first thing to fail was an image build, away from the change that
// caused it.
//
// Both files carry a comment saying to keep the tags aligned. A comment
// is what was there when it drifted.
func TestBuilderImagesSatisfyGoMod(t *testing.T) {
	required := goDirective(t, repoFile(t, "go.mod"))
	require.NotEmpty(t, required, "go.mod must carry a `go` directive")

	for _, file := range []string{"dockerfiles/worker", "dockerfiles/gobuild"} {
		t.Run(file, func(t *testing.T) {
			pinned := golangImageTag(t, repoFile(t, file))
			require.NotEmptyf(t, pinned, "%s names no golang image; this guard is not looking at anything", file)
			assert.GreaterOrEqualf(t, compareVersions(pinned, required), 0,
				"%s pins golang:%s but go.mod requires go >= %s, and GOTOOLCHAIN=local will not upgrade it",
				file, pinned, required)
		})
	}
}

func repoFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../../" + name)
	require.NoError(t, err)
	return string(raw)
}

func goDirective(t *testing.T, gomod string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+(?:\.\d+)?)`).FindStringSubmatch(gomod)
	if m == nil {
		return ""
	}
	return m[1]
}

func golangImageTag(t *testing.T, dockerfile string) string {
	t.Helper()
	m := regexp.MustCompile(`golang:(\d+\.\d+(?:\.\d+)?)-`).FindStringSubmatch(dockerfile)
	if m == nil {
		return ""
	}
	return m[1]
}

// compareVersions compares dotted numeric versions, padding the shorter
// one with zeroes so 1.27 and 1.27.0 compare equal.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for len(as) < len(bs) {
		as = append(as, "0")
	}
	for len(bs) < len(as) {
		bs = append(bs, "0")
	}
	for i := range as {
		av, bv := atoi(as[i]), atoi(bs[i])
		switch {
		case av < bv:
			return -1
		case av > bv:
			return 1
		}
	}
	return 0
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}
