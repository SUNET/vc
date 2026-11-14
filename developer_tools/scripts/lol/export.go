package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const dateLayout = "2006-01-02"

type signerEntry struct {
	n       int
	label   string
	added   []*x509.Certificate
	failure string
}

// exportRequest is what runExport needs; the LoTL must already be verified against the pin.
type exportRequest struct {
	out        string
	pinnedFile string
	lotlURL    string
	signer     signerResult
	info       schemeInfo
	now        time.Time
}

// bundleWriter collects certificates for the bundle, skipping duplicates.
type bundleWriter struct {
	buf     strings.Builder
	seen    map[[32]byte]bool
	written int
}

func (b *bundleWriter) add(label string, cert *x509.Certificate) {
	fp := sha256.Sum256(cert.Raw)
	if b.seen[fp] {
		return
	}
	b.seen[fp] = true
	b.written++
	fmt.Fprintf(&b.buf, "\n# %s\n# %s, expires %s, sha256 %s\n", oneLine(label), oneLine(cert.Subject.String()),
		cert.NotAfter.UTC().Format(dateLayout), hex.EncodeToString(fp[:]))
	_ = pem.Encode(&b.buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// runExport writes the pinned certificates plus every list signer that its own list backs,
// and returns the process exit code.
func runExport(ctx context.Context, c *http.Client, req exportRequest) int {
	pinned, err := readCerts(req.pinnedFile)
	if err != nil {
		fatal(err)
	}

	entries := make([]signerEntry, len(req.info.PointersToOtherLoTE))
	for i, p := range req.info.PointersToOtherLoTE {
		entries[i] = bindPointer(ctx, c, i+1, p, req.now)
	}

	w := &bundleWriter{seen: map[[32]byte]bool{}}
	fmt.Fprintf(&w.buf, "# trust_anchor_bundle written by lol on %s\n# LoTL: %s\n", req.now.UTC().Format(dateLayout), req.lotlURL)
	for _, cert := range pinned {
		w.add("LoTL signer (pinned by you)", cert)
	}
	pinnedCount := w.written

	leftOut := 0
	for _, e := range entries {
		if e.failure != "" {
			leftOut++
			continue
		}
		for _, cert := range e.added {
			w.add(fmt.Sprintf("%s (list #%d)", e.label, e.n), cert)
		}
	}

	printField("LoTL", req.lotlURL)
	printField("Signer", paint(colorGreen, "signature ok")+" "+req.signer.Subject)
	printField("Output", req.out)
	printExportTable(entries)

	// public certificates only, so world-readable is fine
	if err := os.WriteFile(req.out, []byte(w.buf.String()), 0o644); err != nil { //nolint:gosec
		fatal(err)
	}
	fmt.Printf("\nWrote %d certificates to %s (%d pinned, %d list signers).\n", w.written, req.out, pinnedCount, w.written-pinnedCount)
	if leftOut == 0 {
		return 0
	}
	fmt.Println(paint(colorRed, fmt.Sprintf("%d lists left out: none of their listed certificates is backed by the list.", leftOut)))
	return 1
}

func printExportTable(entries []signerEntry) {
	kindMax := 1 << 20
	if w := terminalWidth(); w > 0 {
		kindMax = max(w-45, 16)
	}
	fmt.Printf("\n%s\n", paint(colorBold, fmt.Sprintf("%2s  %s  %s  %s  %s",
		"#", pad("RESULT", 6), pad("EXPIRES", 10), pad("SHA256", 8), "KIND")))
	for _, e := range entries {
		kind := trunc(e.label, kindMax)
		if e.failure != "" {
			fmt.Printf("%2d  %s  %s  %s  %s\n", e.n, paint(colorRed, pad("SKIP", 6)),
				pad("-", 10), pad("-", 8), kind)
			printDetail("reason", paint(colorRed, e.failure))
			continue
		}
		for _, cert := range e.added {
			fp := sha256.Sum256(cert.Raw)
			fmt.Printf("%2d  %s  %s  %s  %s\n", e.n, paint(colorGreen, pad("ADDED", 6)),
				pad(cert.NotAfter.UTC().Format(dateLayout), 10), hex.EncodeToString(fp[:4]), kind)
		}
	}
}

// bindPointer keeps a pointer's certificate only when the list it points to is signed by it.
func bindPointer(ctx context.Context, c *http.Client, n int, p pointer, now time.Time) signerEntry {
	e := signerEntry{n: n, label: p.LoTELocation}
	if len(p.LoTEQualifiers) > 0 {
		e.label = shortType(p.LoTEQualifiers[0].LoTEType)
	}

	certs, err := pointerCerts(p)
	if err != nil {
		e.failure = err.Error()
		return e
	}
	body, err := fetch(ctx, c, p.LoTELocation)
	if err != nil {
		e.failure = err.Error()
		return e
	}
	if meta, err := parseList(body, mime(p)); err == nil && meta.kind != "" {
		e.label = meta.kind
	}

	var first error
	for _, cert := range certs {
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		if _, _, err := verifyList(ctx, body, pool, now); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		e.added = append(e.added, cert)
	}
	if len(e.added) == 0 {
		e.failure = first.Error()
	}
	return e
}

func pointerCerts(p pointer) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, sdi := range p.ServiceDigitalIdentities {
		for _, x := range sdi.X509Certificates {
			cert, err := parseB64Cert(x.Val)
			if err != nil {
				return nil, fmt.Errorf("pointer certificate: %w", err)
			}
			out = append(out, cert)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("pointer lists no certificate")
	}
	return out, nil
}

func parseB64Cert(s string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func readCerts(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, cert)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no certificates found", path)
	}
	return out, nil
}

// oneLine keeps list-supplied text from breaking out of a PEM comment.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
