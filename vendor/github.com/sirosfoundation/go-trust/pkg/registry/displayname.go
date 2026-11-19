package registry

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// maxDisplayNameLen bounds a display name in runes.
const maxDisplayNameLen = 200

// SanitizeDisplayName makes a registry-supplied name safe to show in a consent
// UI: whitespace is collapsed and trimmed, control, format (which includes the
// bidirectional overrides) and other non-printing characters are dropped, and
// the result is capped at maxDisplayNameLen runes. It returns "" when nothing
// printable remains.
func SanitizeDisplayName(name string) string {
	if !utf8.ValidString(name) {
		name = strings.ToValidUTF8(name, "")
	}
	var b strings.Builder
	space := false
	n := 0
	for _, r := range name {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), !unicode.IsPrint(r):
			continue
		}
		if n >= maxDisplayNameLen {
			break
		}
		if space {
			b.WriteByte(' ')
			n++
			space = false
			if n >= maxDisplayNameLen {
				break
			}
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// maxDisplayNameLangs bounds the number of languages in display_name_l10n.
const maxDisplayNameLangs = 32

var langTagRE = regexp.MustCompile(`^[a-z]{2,3}(-[a-z0-9]{1,8})*$`)

// SanitizeDisplayNameL10n sanitizes a language-tag to name map: tags are
// lower-cased and must look like BCP 47 tags, names are sanitized, entries that
// fail either test are dropped, and at most maxDisplayNameLangs entries are kept
// (in lexical tag order, so the result is reproducible). It returns nil when
// nothing remains.
func SanitizeDisplayNameL10n(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	tags := make([]string, 0, len(in))
	for tag := range in {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	out := make(map[string]string, len(in))
	for _, tag := range tags {
		lang := strings.ToLower(strings.TrimSpace(tag))
		name := SanitizeDisplayName(in[tag])
		if _, dup := out[lang]; dup || !langTagRE.MatchString(lang) || len(lang) > 35 || name == "" {
			continue
		}
		if len(out) >= maxDisplayNameLangs {
			break
		}
		out[lang] = name
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// OriginDomain derives the normalized domain name of the site a subject
// identifier names: the lower-case host of an http(s) URL, of a did:web
// identifier, or of an x509_san_dns/x509_san_uri client_id, without port,
// userinfo or a trailing dot. Internationalized names stay in their ASCII
// (punycode) form. It returns "" for identifiers that do not name a site (hash
// identifiers, URNs, IP addresses).
func OriginDomain(id string) string {
	id = strings.TrimSpace(id)
	var host string
	switch {
	case strings.HasPrefix(id, "x509_san_dns:"):
		host = strings.TrimPrefix(id, "x509_san_dns:")
	case strings.HasPrefix(id, "x509_san_uri:"):
		host = hostOfURL(strings.TrimPrefix(id, "x509_san_uri:"))
	case strings.HasPrefix(id, "did:web:"):
		host = strings.SplitN(strings.TrimPrefix(id, "did:web:"), ":", 2)[0]
		if u, err := url.PathUnescape(host); err == nil {
			host = u
		}
		host = stripPort(host)
	case strings.HasPrefix(id, "https://"), strings.HasPrefix(id, "http://"):
		host = hostOfURL(id)
	default:
		return ""
	}
	return normalizeHost(host)
}

func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.Hostname()
}

func stripPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return ""
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return ""
			}
		}
	}
	return h
}

// applyDisplayName ensures a positive response carries a display_name: the
// registry-supplied one (already merged by the strategy) or, failing that, the
// origin domain of the subject. Denials are left untouched.
func applyDisplayName(req *authzen.EvaluationRequest, resp *authzen.EvaluationResponse) {
	if resp == nil || !resp.Decision {
		return
	}
	if resp.Context != nil {
		if name := SanitizeDisplayName(resp.Context.DisplayName); name != "" {
			resp.Context.DisplayName = name
			resp.Context.DisplayNameL10n = SanitizeDisplayNameL10n(resp.Context.DisplayNameL10n)
			return
		}
		resp.Context.DisplayName = ""
		resp.Context.DisplayNameL10n = nil
	}
	if req == nil {
		return
	}
	// An overlong domain is omitted rather than truncated into a misleading host.
	if origin := OriginDomain(req.Subject.ID); origin != "" && len(origin) <= maxDisplayNameLen {
		if resp.Context == nil {
			resp.Context = &authzen.EvaluationResponseContext{}
		}
		resp.Context.DisplayName = origin
	}
}

// mergeDisplayName carries a child registry's display_name (#249) onto an
// aggregated response. The strategies that combine several registries build a
// fresh context out of the children's results, so without this the name is
// dropped before it reaches the wallet even when exactly one registry named
// the trust subject.
//
// Only an unambiguous name travels. When the agreeing children carry more than
// one distinct name the aggregate has no single subject to label, so it stays
// unnamed: display_name overrides the verifier's own label downstream, and
// presenting one of several disagreeing names would suppress the right one.
// Absence is a supported outcome (applyDisplayName then falls back to the
// origin domain), and a name only a denying child carried never travels at
// all, because children is the set that agreed with the decision. The
// display_name_l10n of the first child that carries the name travels with it,
// so the two members always describe the same entity.
func mergeDisplayName(resp *authzen.EvaluationResponse, children []*authzen.EvaluationResponse) {
	if resp == nil || !resp.Decision {
		return
	}

	var best *authzen.EvaluationResponseContext
	for _, c := range children {
		if c == nil || !c.Decision || c.Context == nil || c.Context.DisplayName == "" {
			continue
		}
		if best != nil && c.Context.DisplayName != best.DisplayName {
			return
		}
		if best == nil || (best.DisplayNameL10n == nil && c.Context.DisplayNameL10n != nil) {
			best = c.Context
		}
	}
	if best == nil {
		return
	}

	if resp.Context == nil {
		resp.Context = &authzen.EvaluationResponseContext{}
	}
	resp.Context.DisplayName = best.DisplayName
	resp.Context.DisplayNameL10n = best.DisplayNameL10n
}
