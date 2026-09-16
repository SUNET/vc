// Command tsl_checker inspects the status of a single Token Status List
// (draft-ietf-oauth-status-list) entry by URI+index, from a credential
// file, or from stdin.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/revocation"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
)

var version = "dev"

const (
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[1;33m"
	colorCyan   = "\033[0;36m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"

	iconOK   = "✅"
	iconFail = "❌"
	iconWarn = "⚠️ "
)

// Exit codes: 0/1/2 mirror the three defined status values (VALID/INVALID/SUSPENDED);
// 3 is any other status byte; 4 is a tool/network/parse error; 5 is a usage error.
const (
	exitValid     = 0
	exitInvalid   = 1
	exitSuspended = 2
	exitOther     = 3
	exitError     = 4
	exitUsage     = 5
)

const (
	httpTimeout       = 30 * time.Second
	maxStatusListSize = 10 << 20
	maxCredentialSize = 1 << 20
)

type result struct {
	URI          string `json:"uri"`
	Index        int64  `json:"idx"`
	Format       string `json:"format"`
	StatusByte   uint8  `json:"status_byte"`
	StatusName   string `json:"status"`
	Verified     bool   `json:"verified"`
	VerifyReason string `json:"verify_reason,omitempty"`
	Source       string `json:"source"`
}

func main() {
	idx := flag.Int64("idx", -1, "Status list index to check (required with -uri)")
	uri := flag.String("uri", "", "Status list URI to fetch")
	credFile := flag.String("credential_file", "", "Path to a credential (SD-JWT VC, JWT, or mdoc)")
	asJSON := flag.Bool("json", false, "Emit result as JSON")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  tsl_checker -idx <int> -uri <string>\n")
		fmt.Fprintf(os.Stderr, "  tsl_checker -credential_file <path>\n")
		fmt.Fprintf(os.Stderr, "  cat <credential> | tsl_checker\n\n")
		fmt.Fprintf(os.Stderr, "Check the status of a Token Status List entry per draft-ietf-oauth-status-list.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	// ContinueOnError so bad flags map to exitUsage instead of the default exit 2.
	flag.CommandLine.Init("tsl_checker", flag.ContinueOnError)
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		os.Exit(exitUsage)
	}

	if *showVersion {
		fmt.Printf("tsl_checker %s\n", version)
		os.Exit(0)
	}

	c := colors(!*noColor && !*asJSON)

	resolvedURI, resolvedIdx, source, err := resolveInput(*uri, *idx, *credFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n\n", c.fail, err)
		flag.Usage()
		os.Exit(exitUsage)
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout+5*time.Second)
	defer cancel()

	res, err := check(ctx, resolvedURI, resolvedIdx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", c.fail, err)
		os.Exit(exitError)
	}
	res.Source = source

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "%s failed to encode JSON: %v\n", c.fail, err)
			os.Exit(exitError)
		}
	} else {
		printPretty(res, c)
	}

	os.Exit(exitForStatus(res.StatusByte))
}

func resolveInput(uri string, idx int64, credFile string) (string, int64, string, error) {
	haveURI := uri != ""
	haveCred := credFile != ""
	stdinPiped := !isatty(os.Stdin)

	switch {
	case haveURI && haveCred:
		return "", 0, "", errors.New("-uri and -credential_file are mutually exclusive")
	case haveURI:
		if idx < 0 {
			return "", 0, "", errors.New("-idx must be >= 0 when using -uri")
		}
		return uri, idx, "uri", nil
	case haveCred:
		f, err := os.Open(filepath.Clean(credFile))
		if err != nil {
			return "", 0, "", fmt.Errorf("read credential file: %w", err)
		}
		defer func() { _ = f.Close() }()
		data, err := io.ReadAll(io.LimitReader(f, maxCredentialSize+1))
		if err != nil {
			return "", 0, "", fmt.Errorf("read credential file: %w", err)
		}
		if int64(len(data)) > maxCredentialSize {
			return "", 0, "", fmt.Errorf("credential file exceeds maximum size (%d bytes)", maxCredentialSize)
		}
		return extractFromCredential(data, "credential_file")
	case stdinPiped:
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxCredentialSize+1))
		if err != nil {
			return "", 0, "", fmt.Errorf("read stdin: %w", err)
		}
		if int64(len(data)) > maxCredentialSize {
			return "", 0, "", fmt.Errorf("stdin credential exceeds maximum size (%d bytes)", maxCredentialSize)
		}
		return extractFromCredential(data, "stdin")
	default:
		return "", 0, "", errors.New("no input: provide -uri and -idx, -credential_file, or pipe credential to stdin")
	}
}

func extractFromCredential(raw []byte, source string) (string, int64, string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "", 0, "", errors.New("empty credential input")
	}

	if strings.HasPrefix(trimmed, "ey") {
		uri, idx, err := extractFromJWT(trimmed)
		if err != nil {
			return "", 0, "", fmt.Errorf("extract from JWT/SD-JWT: %w", err)
		}
		return uri, idx, source, nil
	}

	uri, idx, err := extractFromMdoc(raw)
	if err != nil {
		return "", 0, "", fmt.Errorf("extract from mdoc: %w", err)
	}
	return uri, idx, source, nil
}

func extractFromJWT(s string) (string, int64, error) {
	// SD-JWT VC: <jwt>~<disclosure>~...~<kb-jwt>?
	jwtPart := s
	if i := strings.IndexByte(s, '~'); i >= 0 {
		jwtPart = s[:i]
	}
	parts := strings.Split(jwtPart, ".")
	if len(parts) < 2 {
		return "", 0, errors.New("not a JWT: fewer than two segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", 0, fmt.Errorf("parse payload: %w", err)
	}
	ref := revocation.ExtractStatusListReference(claims)
	if ref == nil {
		return "", 0, errors.New("no status.status_list claim in credential")
	}
	return ref.URI, ref.Index, nil
}

func extractFromMdoc(raw []byte) (string, int64, error) {
	var lastErr error
	for _, data := range mdocDecodeCandidates(raw) {
		if uri, idx, ok, err := tryExtractMdocDoc(data); ok {
			return uri, idx, nil
		} else if err != nil {
			lastErr = err
		}
		if uri, idx, ok, err := tryExtractMdocResponse(data); ok {
			return uri, idx, nil
		} else if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return "", 0, lastErr
	}
	return "", 0, errors.New("input is neither JWT/SD-JWT nor recognizable mdoc CBOR")
}

func tryExtractMdocDoc(data []byte) (string, int64, bool, error) {
	var doc mdoc.DocumentMdoc
	if err := cbor.Unmarshal(data, &doc); err != nil {
		return "", 0, false, nil
	}
	ref, err := mdoc.ExtractStatusReference(&doc)
	if err != nil {
		return "", 0, false, err
	}
	return ref.URI, ref.Index, true, nil
}

func tryExtractMdocResponse(data []byte) (string, int64, bool, error) {
	var resp mdoc.DeviceResponseMdoc
	if err := cbor.Unmarshal(data, &resp); err != nil {
		return "", 0, false, nil
	}
	var lastErr error
	for i := range resp.Documents {
		ref, err := mdoc.ExtractStatusReference(&resp.Documents[i])
		if err != nil {
			lastErr = err
			continue
		}
		return ref.URI, ref.Index, true, nil
	}
	return "", 0, false, lastErr
}

// mdocDecodeCandidates returns possible raw CBOR forms of an mdoc credential.
// Order: raw bytes first, then base64url, then hex — cheapest sniff first.
func mdocDecodeCandidates(raw []byte) [][]byte {
	out := [][]byte{raw}
	txt := strings.TrimSpace(string(raw))
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(txt, "=")); err == nil && len(b) > 0 {
		out = append(out, b)
	}
	if b, err := base64.StdEncoding.DecodeString(txt); err == nil && len(b) > 0 {
		out = append(out, b)
	}
	if b, err := hex.DecodeString(txt); err == nil && len(b) > 0 {
		out = append(out, b)
	}
	return out
}

func check(ctx context.Context, uri string, idx int64) (*result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	switch req.URL.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported status list URI scheme: %q", req.URL.Scheme)
	}
	req.Header.Set("Accept", fmt.Sprintf("%s, %s", tokenstatuslist.MediaTypeJWT, tokenstatuslist.MediaTypeCWT))

	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch status list: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status list request failed with HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusListSize+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > maxStatusListSize {
		return nil, fmt.Errorf("status list response exceeds maximum size (%d bytes)", maxStatusListSize)
	}

	format := detectFormat(resp.Header.Get("Content-Type"), body)
	res := &result{URI: uri, Index: idx, Format: format}

	switch format {
	case "JWT":
		if err := checkJWT(body, idx, res); err != nil {
			return nil, err
		}
	case "CWT":
		if err := checkCWT(body, idx, res); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown status list format")
	}

	res.StatusName = statusName(res.StatusByte)
	return res, nil
}

func detectFormat(contentType string, body []byte) string {
	switch contentType {
	case tokenstatuslist.MediaTypeJWT:
		return "JWT"
	case tokenstatuslist.MediaTypeCWT:
		return "CWT"
	}
	if len(body) > 0 && body[0] == 0xD2 {
		return "CWT"
	}
	return "JWT"
}

func checkJWT(body []byte, idx int64, res *result) error {
	tokenStr := strings.TrimSpace(string(body))

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("parse JWT: %w", err)
	}

	if hdr, present := unverified.Header["jwk"]; present {
		// An embedded jwk asserts a signer; treat any failure as fatal so callers cannot consume an unauthenticated status.
		jwkHdr, ok := hdr.(map[string]any)
		if !ok {
			return fmt.Errorf("embedded jwk header has invalid type %T", hdr)
		}
		pub, err := jose.ParseJWKToPublicKey(jwkHdr)
		if err != nil {
			return fmt.Errorf("embedded jwk unusable: %w", err)
		}
		claims, err := tokenstatuslist.ParseJWT(tokenStr, func(t *jwt.Token) (any, error) {
			if err := ensureStrongAlg(t.Method.Alg(), pub); err != nil {
				return nil, err
			}
			return pub, nil
		})
		if err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
		res.Verified = true
		b, err := statusFromJWTClaims(claims, idx)
		if err != nil {
			return fmt.Errorf("extract status from JWT: %w", err)
		}
		res.StatusByte = b
		return nil
	}
	res.VerifyReason = "no jwk header embedded; signature not verified"

	claims, err := parseJWTClaimsUnverified(tokenStr)
	if err != nil {
		return fmt.Errorf("parse JWT claims: %w", err)
	}
	b, err := statusFromJWTClaims(claims, idx)
	if err != nil {
		return fmt.Errorf("extract status from JWT: %w", err)
	}
	res.StatusByte = b
	return nil
}

// statusFromJWTClaims decodes the compressed lst and returns the status at idx,
// honoring StatusList.Bits (1, 2, 4, or 8) per draft-ietf-oauth-status-list.
func statusFromJWTClaims(claims *tokenstatuslist.JWTClaims, idx int64) (uint8, error) {
	statuses, err := tokenstatuslist.DecodeAndDecompress(claims.StatusList.Lst)
	if err != nil {
		return 0, fmt.Errorf("decode status list: %w", err)
	}
	return statusAt(statuses, claims.StatusList.Bits, idx)
}

// statusAt unpacks a single status entry from the decompressed lst.
func statusAt(lst []byte, bits int, idx int64) (uint8, error) {
	switch bits {
	case 1, 2, 4, 8:
	default:
		return 0, fmt.Errorf("unsupported status list bits value: %d", bits)
	}
	if idx < 0 {
		return 0, fmt.Errorf("index out of range: %d", idx)
	}
	entriesPerByte := int64(8 / bits)
	byteIdx := idx / entriesPerByte
	if byteIdx >= int64(len(lst)) {
		return 0, fmt.Errorf("index %d out of range for status list of %d entries", idx, int64(len(lst))*entriesPerByte)
	}
	shift := uint((idx % entriesPerByte) * int64(bits))
	mask := uint8((1 << bits) - 1)
	return (lst[byteIdx] >> shift) & mask, nil
}

func parseJWTClaimsUnverified(tokenStr string) (*tokenstatuslist.JWTClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 {
		return nil, errors.New("malformed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims tokenstatuslist.JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return &claims, nil
}

// ensureStrongAlg rejects "none", HMAC ("HS*"), and any algorithm that does
// not match the resolved public key type. For ECDSA it also enforces the JWA
// alg↔curve pairing (ES256/P-256, ES384/P-384, ES512/P-521). Prevents JWT
// algorithm-confusion.
func ensureStrongAlg(alg string, pub any) error {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		curve := key.Curve.Params().Name
		switch alg {
		case "ES256":
			if curve == "P-256" {
				return nil
			}
		case "ES384":
			if curve == "P-384" {
				return nil
			}
		case "ES512":
			if curve == "P-521" {
				return nil
			}
		default:
			return fmt.Errorf("disallowed JWT alg %q for key type %T", alg, pub)
		}
		return fmt.Errorf("JWT alg %q incompatible with EC curve %q", alg, curve)
	case *rsa.PublicKey:
		switch alg {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			return nil
		}
	case ed25519.PublicKey:
		if alg == "EdDSA" {
			return nil
		}
	}
	return fmt.Errorf("disallowed JWT alg %q for key type %T", alg, pub)
}

func checkCWT(body []byte, idx int64, res *result) error {
	res.VerifyReason = "CWT signature verification not supported"
	claims, err := tokenstatuslist.ParseCWT(body)
	if err != nil {
		return fmt.Errorf("parse CWT: %w", err)
	}
	lst, bits, err := extractCWTStatusList(claims)
	if err != nil {
		return fmt.Errorf("extract status_list from CWT: %w", err)
	}
	statuses, err := tokenstatuslist.DecompressStatuses(lst)
	if err != nil {
		return fmt.Errorf("decompress CWT status list: %w", err)
	}
	b, err := statusAt(statuses, bits, idx)
	if err != nil {
		return fmt.Errorf("extract status from CWT: %w", err)
	}
	res.StatusByte = b
	return nil
}

// extractCWTStatusList reads lst and bits from a parsed CWT claim map,
// tolerating the map key shapes produced by different CBOR decoders.
func extractCWTStatusList(claims map[int]any) ([]byte, int, error) {
	raw, ok := claims[65534]
	if !ok {
		return nil, 0, errors.New("status_list claim not found")
	}
	var lst []byte
	bits := 0
	switch sl := raw.(type) {
	case map[int]any:
		lst, _ = sl[2].([]byte)
		bits = cwtIntField(sl[1])
	case map[any]any:
		for k, v := range sl {
			switch cwtNormalizeKey(k) {
			case 1:
				bits = cwtIntField(v)
			case 2:
				if b, ok := v.([]byte); ok {
					lst = b
				}
			}
		}
	default:
		return nil, 0, fmt.Errorf("invalid status_list claim format: %T", raw)
	}
	if lst == nil {
		return nil, 0, errors.New("lst not found in status_list")
	}
	if bits == 0 {
		return nil, 0, errors.New("bits not found in status_list")
	}
	return lst, bits, nil
}

func cwtNormalizeKey(k any) int {
	switch v := k.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint64:
		return int(v)
	default:
		return -1
	}
}

func cwtIntField(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	default:
		return 0
	}
}

func statusName(b uint8) string {
	switch b {
	case tokenstatuslist.StatusValid:
		return "VALID"
	case tokenstatuslist.StatusInvalid:
		return "INVALID"
	case tokenstatuslist.StatusSuspended:
		return "SUSPENDED"
	default:
		return fmt.Sprintf("OTHER(%d)", b)
	}
}

func exitForStatus(b uint8) int {
	switch b {
	case tokenstatuslist.StatusValid:
		return exitValid
	case tokenstatuslist.StatusInvalid:
		return exitInvalid
	case tokenstatuslist.StatusSuspended:
		return exitSuspended
	default:
		return exitOther
	}
}

func printPretty(r *result, c colorSet) {
	statusIcon := c.ok
	statusColor := colorGreen
	switch r.StatusByte {
	case tokenstatuslist.StatusInvalid:
		statusIcon = c.fail
		statusColor = colorRed
	case tokenstatuslist.StatusSuspended:
		statusIcon = c.warn
		statusColor = colorYellow
	default:
		if r.StatusByte != tokenstatuslist.StatusValid {
			statusIcon = c.warn
			statusColor = colorYellow
		}
	}

	fmt.Printf("%s=== Token Status List Check ===%s\n", c.heading, c.reset)
	fmt.Printf("Source:   %s%s%s\n", c.cyan, r.Source, c.reset)
	fmt.Printf("URI:      %s%s%s\n", c.cyan, r.URI, c.reset)
	fmt.Printf("Index:    %s%d%s\n", c.cyan, r.Index, c.reset)
	fmt.Printf("Format:   %s\n", r.Format)
	if r.Verified {
		fmt.Printf("Verified: %s (embedded jwk)\n", c.ok)
	} else {
		reason := r.VerifyReason
		if reason == "" {
			reason = "not verified"
		}
		fmt.Printf("Verified: %s %s\n", c.warn, reason)
	}
	if c.reset == "" {
		fmt.Printf("Status:   %s %s (0x%02x)\n", statusIcon, r.StatusName, r.StatusByte)
	} else {
		fmt.Printf("Status:   %s %s%s%s (0x%02x)\n", statusIcon, statusColor, r.StatusName, c.reset, r.StatusByte)
	}
}

func isatty(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return true
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

type colorSet struct {
	ok, fail, warn, cyan, bold, heading, reset string
}

func colors(enabled bool) colorSet {
	if !enabled {
		return colorSet{ok: iconOK, fail: iconFail, warn: iconWarn}
	}
	return colorSet{
		ok:      colorGreen + iconOK + colorReset,
		fail:    colorRed + iconFail + colorReset,
		warn:    colorYellow + iconWarn + colorReset,
		cyan:    colorCyan,
		bold:    colorBold,
		heading: colorYellow + colorBold,
		reset:   colorReset,
	}
}
