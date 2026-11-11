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

type signerEntry struct {
	n       int
	label   string
	added   []*x509.Certificate
	failure string
}

// runExport writes the pinned certificates plus every list signer that its own list backs,
// and returns the process exit code. The LoTL must already be verified against the pin.
func runExport(ctx context.Context, c *http.Client, out, pinnedFile, lotlURL string, signer signerResult, info schemeInfo, now time.Time) int {
	pinned, err := readCerts(pinnedFile)
	if err != nil {
		fatal(err)
	}

	entries := make([]signerEntry, len(info.PointersToOtherLoTE))
	for i, p := range info.PointersToOtherLoTE {
		entries[i] = bindPointer(ctx, c, i+1, p, now)
	}

	var buf strings.Builder
	fmt.Fprintf(&buf, "# trust_anchor_bundle written by lol on %s\n# LoTL: %s\n", now.UTC().Format("2006-01-02"), lotlURL)
	seen := map[[32]byte]bool{}
	written := 0
	add := func(label string, cert *x509.Certificate) {
		fp := sha256.Sum256(cert.Raw)
		if seen[fp] {
			return
		}
		seen[fp] = true
		written++
		fmt.Fprintf(&buf, "\n# %s\n# %s, expires %s, sha256 %s\n", oneLine(label), oneLine(cert.Subject.String()),
			cert.NotAfter.UTC().Format("2006-01-02"), hex.EncodeToString(fp[:]))
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	for _, cert := range pinned {
		add("LoTL signer (pinned by you)", cert)
	}
	pinnedCount := written

	leftOut := 0
	for _, e := range entries {
		if e.failure != "" {
			leftOut++
			continue
		}
		for _, cert := range e.added {
			add(fmt.Sprintf("%s (list #%d)", e.label, e.n), cert)
		}
	}

	printField("LoTL", lotlURL)
	printField("Signer", paint(colorGreen, "signature ok")+" "+signer.Subject)
	printField("Output", out)

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
				pad(cert.NotAfter.UTC().Format("2006-01-02"), 10), hex.EncodeToString(fp[:4]), kind)
		}
	}

	// public certificates only, so world-readable is fine
	if err := os.WriteFile(out, []byte(buf.String()), 0o644); err != nil { //nolint:gosec
		fatal(err)
	}
	fmt.Printf("\nWrote %d certificates to %s (%d pinned, %d list signers).\n", written, out, pinnedCount, written-pinnedCount)
	if leftOut > 0 {
		fmt.Println(paint(colorRed, fmt.Sprintf("%d lists left out: none of their listed certificates is backed by the list.", leftOut)))
	}

	if leftOut > 0 {
		return 1
	}
	return 0
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
		if _, err := verifyList(ctx, body, pool, now); err != nil {
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
