// Command lol fetches a List of Trusted Lists (LoTL) and reports the state of
// every list it points to: reachable, signer chain, NextUpdate.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

var version = "dev"

const (
	defaultLoTL = "https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.json"
	maxBody     = 10 << 20

	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[1;33m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorReset  = "\033[0m"
)

var useColor = colorEnabled()

func colorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func paint(color, s string) string {
	if !useColor || color == "" {
		return s
	}
	return color + s + colorReset
}

func stateColor(state string) string {
	switch state {
	case "OK":
		return colorGreen
	case "STALE":
		return colorYellow
	}
	return colorRed
}

func sigColor(sig string) string {
	switch sig {
	case "ok":
		return colorGreen
	case "FAIL":
		return colorRed
	}
	return ""
}

type name struct{ Lang, Value string }

type qualifier struct {
	LoTEType           string
	MimeType           string
	SchemeTerritory    string
	SchemeOperatorName []name
}

type pointer struct {
	LoTELocation             string
	LoTEQualifiers           []qualifier
	ServiceDigitalIdentities []struct {
		X509Certificates []struct{ Val string }
	}
}

type schemeInfo struct {
	LoTEType            string
	SchemeName          []name
	ListIssueDateTime   string
	NextUpdate          string
	PointersToOtherLoTE []pointer
}

type jsonList struct {
	LoTE struct {
		ListAndSchemeInformation schemeInfo
	}
}

type xmlList struct {
	TSLNext  string   `xml:"SchemeInformation>NextUpdate>dateTime"`
	LoTENext string   `xml:"ListAndSchemeInformation>NextUpdate>dateTime"`
	TSLName  []string `xml:"SchemeInformation>SchemeName>Name"`
	LoTEName []string `xml:"ListAndSchemeInformation>SchemeName>Name>NonEmptyNormalizedString"`
}

func main() {
	lotlURL := flag.String("lotl", defaultLoTL, "LoTL URL")
	anchorFile := flag.String("anchors", "", "PEM file with trust anchors (go-trust trust_anchor_bundle)")
	timeout := flag.Duration("timeout", 30*time.Second, "per-request timeout")
	showVersion := flag.Bool("version", false, "print version and exit")
	verbose := flag.Bool("v", false, "show full kind, operator, type, format and URL for every list")
	asJSON := flag.Bool("json", false, "print a JSON report instead of the table")
	exportFile := flag.String("export-anchors", "", "write a trust_anchor_bundle PEM: the -anchors certificates plus each list signer its own list backs")
	showFP := flag.Bool("show_fingerprint", false, "print the SHA-256 fingerprint of each signer certificate (needs -anchors)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	checkFlags(*anchorFile, *exportFile, *asJSON, *showFP)
	roots := anchorPool(*anchorFile)

	client := &http.Client{Timeout: *timeout}
	ctx := context.Background()
	now := time.Now()

	signer, info := loadLoTL(ctx, client, *lotlURL, roots, now, *showFP)

	if *exportFile != "" {
		os.Exit(exportBundle(ctx, client, exportRequest{out: *exportFile, pinnedFile: *anchorFile, lotlURL: *lotlURL, signer: signer, info: info, now: now}))
	}

	if !*asJSON {
		printHeader(*lotlURL, info, signer, now)
	}

	rows, counts := checkPointers(ctx, client, info, roots, now, *showFP)
	if *asJSON {
		writeJSON(*lotlURL, info, signer, rows, counts, now)
	} else {
		printReport(rows, counts, now, tableOptions{verbose: *verbose, showSig: roots != nil, showFP: *showFP})
	}

	if signer.State == "failed" || counts["STALE"] > 0 || counts["FAIL"] > 0 {
		os.Exit(1)
	}
}

// checkFlags rejects flag combinations that cannot work.
func checkFlags(anchorFile, exportFile string, asJSON, showFP bool) {
	if exportFile != "" && (anchorFile == "" || asJSON) {
		fatal(errors.New("-export-anchors needs -anchors (the pinned LoTL signer) and cannot be combined with -json"))
	}
	if showFP && anchorFile == "" {
		fatal(errors.New("-show_fingerprint needs -anchors: a signer is only known once a signature is checked"))
	}
}

// anchorPool loads the trust anchors, or returns nil when none were given.
func anchorPool(anchorFile string) *x509.CertPool {
	if anchorFile == "" {
		return nil
	}
	roots, err := loadAnchors(anchorFile)
	if err != nil {
		fatal(err)
	}
	return roots
}

// exportBundle refuses to export unless the LoTL signature verified against the pin.
func exportBundle(ctx context.Context, client *http.Client, req exportRequest) int {
	if req.signer.State != "ok" {
		fatal(fmt.Errorf("refusing to export, LoTL signature not verified against %s: %s", req.pinnedFile, req.signer.Error))
	}
	return runExport(ctx, client, req)
}

func printHeader(lotlURL string, info schemeInfo, signer signerResult, now time.Time) {
	printField("LoTL", lotlURL)
	printField("Type", shortType(info.LoTEType))
	printField("Issued", when(info.ListIssueDateTime, now))
	printField("Next", when(info.NextUpdate, now))
	printField("Signer", signer.text())
	if signer.Fingerprint != "" {
		printField("SHA256", signer.Fingerprint)
	}
}

// loadLoTL fetches the LoTL and, when there are anchors, verifies its signature.
func loadLoTL(ctx context.Context, client *http.Client, url string, roots *x509.CertPool, now time.Time, showFP bool) (signerResult, schemeInfo) {
	body, err := fetch(ctx, client, url)
	if err != nil {
		fatal(fmt.Errorf("fetch LoTL: %w", err))
	}
	content, signer := body, signerResult{State: "not_checked"}
	if roots != nil {
		if subj, fp, err := verifyList(ctx, body, roots, now); err != nil {
			signer = signerResult{State: "failed", Error: err.Error()}
		} else {
			content, signer = payloadOf(body), signerResult{State: "ok", Subject: subj}
			if showFP {
				signer.Fingerprint = fp
			}
		}
	}

	var lotl jsonList
	if err := json.Unmarshal(content, &lotl); err != nil {
		fatal(fmt.Errorf("parse LoTL: %w", err))
	}
	return signer, lotl.LoTE.ListAndSchemeInformation
}

func checkPointers(ctx context.Context, client *http.Client, info schemeInfo, roots *x509.CertPool, now time.Time, showFP bool) ([]row, map[string]int) {
	rows := make([]row, len(info.PointersToOtherLoTE))
	counts := map[string]int{}
	for i, p := range info.PointersToOtherLoTE {
		rows[i] = newRow(i+1, p)
		rows[i].res = checkPointer(ctx, client, p, roots, now, showFP)
		counts[rows[i].res.state]++
		counts["sig:"+rows[i].res.sig]++
	}
	return rows, counts
}

// tableOptions are the display switches for the per-list table.
type tableOptions struct {
	verbose, showSig, showFP bool
}

func printReport(rows []row, counts map[string]int, now time.Time, opt tableOptions) {
	printTable(rows, now, opt)

	fmt.Printf("\n%s  %s  %s  %s\n", paint(colorBold, "Summary"),
		count(colorGreen, counts["OK"], "ok"),
		count(colorYellow, counts["STALE"], "stale"),
		count(colorRed, counts["FAIL"], "failed"))
	if opt.showSig {
		fmt.Println("SIG: ok = signature verified against the anchors, FAIL = not verified")
	}
}

type result struct {
	state  string
	sig    string // ok, FAIL or - (no anchors)
	kind   string // the list's own scheme name, e.g. "QEAA Providers"
	next   time.Time
	detail string

	signerFP string // SHA-256 of the signer certificate; set only with -show_fingerprint
}

type row struct {
	n         int
	typ       string
	typeURI   string
	format    string
	operator  string
	territory string
	location  string
	res       result
}

func newRow(n int, p pointer) row {
	r := row{n: n, location: p.LoTELocation}
	if len(p.LoTEQualifiers) > 0 {
		q := p.LoTEQualifiers[0]
		r.typ = shortType(q.LoTEType)
		r.typeURI = q.LoTEType
		r.format = q.MimeType
		r.territory = q.SchemeTerritory
		if len(q.SchemeOperatorName) > 0 {
			r.operator = q.SchemeOperatorName[0].Value
		}
	}
	return r
}

func checkPointer(ctx context.Context, c *http.Client, p pointer, roots *x509.CertPool, now time.Time, showFP bool) result {
	body, err := fetch(ctx, c, p.LoTELocation)
	if err != nil {
		return result{state: "FAIL", sig: "-", detail: err.Error()}
	}

	content, sig, signerFP := body, "-", ""
	if roots != nil {
		_, fp, err := verifyList(ctx, body, roots, now)
		if err != nil {
			return result{state: "FAIL", sig: "FAIL", detail: "signature: " + err.Error()}
		}
		content, sig = payloadOf(body), "ok"
		if showFP {
			signerFP = fp
		}
	}

	meta, err := parseList(content, mime(p))
	if err != nil {
		return result{state: "FAIL", sig: sig, detail: err.Error()}
	}
	if now.After(meta.next) {
		return result{state: "STALE", sig: sig, kind: meta.kind, next: meta.next, signerFP: signerFP, detail: "expired " + relative(meta.next, now) + "; go-trust skips this list"}
	}
	return result{state: "OK", sig: sig, kind: meta.kind, next: meta.next, signerFP: signerFP}
}

// columnWidths picks the kind and operator column widths, truncating only when the
// terminal is too narrow; piped output stays complete.
func columnWidths(kinds []string, rows []row, showSig bool) (kindW, opW int) {
	kindNeed, opNeed := len("KIND"), len("OPERATOR")
	for i, r := range rows {
		kindNeed = max(kindNeed, utf8.RuneCountInString(kinds[i]))
		opNeed = max(opNeed, utf8.RuneCountInString(r.operator))
	}

	width := terminalWidth()
	if width == 0 {
		width = 1 << 20
	}
	fixed := 35 // the other columns and gaps
	if showSig {
		fixed += 6
	}
	avail := width - fixed
	opMax, kindMax := opNeed, kindNeed
	if kindNeed+opNeed > avail {
		opMax = min(opNeed, max(14, avail/3))
		kindMax = max(avail-opMax, 12)
	}
	return min(kindNeed, kindMax), opMax
}

func printTable(rows []row, now time.Time, opt tableOptions) {
	kinds := make([]string, len(rows))
	for i, r := range rows {
		kinds[i] = r.res.kind
		if kinds[i] == "" {
			kinds[i] = r.typ
		}
	}
	kindW, opW := columnWidths(kinds, rows, opt.showSig)
	for i := range kinds {
		kinds[i] = trunc(kinds[i], kindW)
	}

	head := fmt.Sprintf("%2s  %s  %s  %s  %s", "#", pad("STATE", 5), pad("KIND", kindW), pad("OPERATOR", opW), "CC")
	if opt.showSig {
		head += "  " + pad("SIG", 4)
	}
	fmt.Printf("\n%s\n", paint(colorBold, head+"  NEXT UPDATE"))
	for i, r := range rows {
		printRow(r, kinds[i], kindW, opW, now, opt)
	}
}

func printRow(r row, kind string, kindW, opW int, now time.Time, opt tableOptions) {
	next := "-"
	if !r.res.next.IsZero() {
		next = r.res.next.UTC().Format(dateLayout) + " " + shortRelative(r.res.next, now)
	}
	color := stateColor(r.res.state)
	line := fmt.Sprintf("%2d  %s  %s  %s  %s", r.n,
		paint(color, pad(r.res.state, 5)), pad(kind, kindW), pad(trunc(r.operator, opW), opW), pad(r.territory, 2))
	if opt.showSig {
		line += "  " + paint(sigColor(r.res.sig), pad(r.res.sig, 4))
	}
	fmt.Println(line + "  " + next)
	if r.res.detail != "" {
		printDetail("issue", paint(color, r.res.detail))
	}
	if opt.verbose {
		printVerboseDetails(r)
	}
	if r.res.signerFP != "" {
		printDetail("signer", r.res.signerFP)
	}
	if opt.verbose || r.res.state != "OK" {
		printDetail("url", r.location)
	}
	if opt.verbose {
		fmt.Println()
	}
}

func printVerboseDetails(r row) {
	if r.res.kind != "" {
		printDetail("kind", r.res.kind)
	}
	printDetail("operator", r.operator)
	printDetail("type", r.typeURI)
	printDetail("format", r.format)
}

func printDetail(label, value string) {
	fmt.Printf("      %s  %s\n", paint(colorDim, pad(label, 8)), value)
}

func printField(label, value string) {
	fmt.Printf("%s  %s\n", paint(colorBold, pad(label, 6)), value)
}

// pad pads before coloring: escape codes would break fmt width.
func pad(s string, w int) string {
	if n := utf8.RuneCountInString(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func count(color string, n int, label string) string {
	s := fmt.Sprintf("%d %s", n, label)
	if n == 0 {
		return s
	}
	return paint(color, s)
}

func shortType(uri string) string {
	if i := strings.LastIndex(uri, "/"); i >= 0 {
		uri = uri[i+1:]
	}
	uri = strings.TrimPrefix(uri, "EU")
	return strings.TrimSuffix(uri, "List")
}

func trunc(s string, w int) string {
	if r := []rune(s); len(r) > w {
		return string(r[:w-1]) + "…"
	}
	return s
}

func shortRelative(t, now time.Time) string {
	d := int(t.Sub(now).Hours() / 24)
	if d < 0 {
		return fmt.Sprintf("%dd", d)
	}
	return fmt.Sprintf("+%dd", d)
}

func when(raw string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return whenTime(t, now)
}

func whenTime(t, now time.Time) string {
	return t.UTC().Format(dateLayout) + "  (" + relative(t, now) + ")"
}

func relative(t, now time.Time) string {
	if d := t.Sub(now); d < 0 {
		return fmt.Sprintf("%dd ago", int(-d.Hours()/24))
	} else {
		return fmt.Sprintf("in %dd", int(d.Hours()/24))
	}
}

type listMeta struct {
	next time.Time
	kind string
}

func parseList(body []byte, mimeType string) (listMeta, error) {
	var raw, kind string
	if strings.Contains(mimeType, "json") {
		var l jsonList
		if err := json.Unmarshal(body, &l); err != nil {
			return listMeta{}, fmt.Errorf("parse JSON list: %w", err)
		}
		info := l.LoTE.ListAndSchemeInformation
		raw = info.NextUpdate
		if len(info.SchemeName) > 0 {
			kind = info.SchemeName[0].Value
		}
	} else {
		var l xmlList
		if err := xml.Unmarshal(body, &l); err != nil {
			return listMeta{}, fmt.Errorf("parse XML list: %w", err)
		}
		raw = strings.TrimSpace(l.TSLNext + l.LoTENext)
		if names := append(l.TSLName, l.LoTEName...); len(names) > 0 {
			kind = names[0]
		}
	}
	if raw == "" {
		return listMeta{}, fmt.Errorf("no NextUpdate found")
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return listMeta{}, fmt.Errorf("NextUpdate %q: %w", raw, err)
	}
	return listMeta{next: t, kind: cleanKind(kind)}, nil
}

// cleanKind drops the "EU:EN_WEBUILD - " style prefix, keeping the list's own name.
func cleanKind(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.LastIndex(s, " - "); i >= 0 {
		s = s[i+3:]
	}
	return s
}

func loadAnchors(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no certificates found", path)
	}
	return pool, nil
}

func fetch(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

func mime(p pointer) string {
	if len(p.LoTEQualifiers) > 0 {
		return p.LoTEQualifiers[0].MimeType
	}
	return ""
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "lol:", err)
	os.Exit(2)
}
