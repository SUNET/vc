// Package lote — classic ETSI TS 119 612 TSL pointers in a LoTL.
//
// A LoTL may point at a classic XML Trusted Status List (TS 119 612, scheme
// type ".../TrstSvc/TrustedList/TSLType/EUgeneric") instead of a TS 119 602
// LoTE. Such pointers are loaded through the TSL parser and converted with
// etsi119602.FromTSL so they are indexed alongside native LoTEs.
//
// When signature verification is on (trust anchors available) a classic TSL is
// never loaded unverified: its XMLDSig must verify and the signer certificate
// must chain to the trust anchors. See verifyTSLSignature.
package lote

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/moov-io/signedxml"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/g119612/pkg/etsi119612"
)

const (
	// classicTSLTypeMarker is the path fragment shared by all TS 119 612 TSL
	// type URIs (e.g. http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric).
	classicTSLTypeMarker = "/TrstSvc/TrustedList/TSLType/"

	xmlDSigNS = "http://www.w3.org/2000/09/xmldsig#"

	// maxKeyInfoCerts bounds the certificates accepted in a signature's
	// KeyInfo. KeyInfo is outside the signed digest, so anyone able to alter
	// the document in transit could otherwise pad it with thousands of
	// certificates to burn CPU in the per-candidate verification loop.
	maxKeyInfoCerts = 8
)

// IsClassicTSLSchemeType reports whether a pointer's scheme type URI names a
// classic ETSI TS 119 612 TSL (EUgeneric, CClist, ...) rather than a LoTE.
func IsClassicTSLSchemeType(schemeType string) bool {
	return strings.Contains(schemeType, classicTSLTypeMarker)
}

// isClassicTSLPointer reports whether a LoTL pointer targets an XML TSL. The
// scheme type decides, unless the pointer's MimeType says the target is JSON:
// a native JSON LoTE may reuse a classic TSLType (e.g. EUgeneric) in its
// qualifier, and must keep loading as a LoTE.
func isClassicTSLPointer(ptr etsi119602.OtherLoTEPointer) bool {
	if !IsClassicTSLSchemeType(pointerSchemeType(ptr)) {
		return false
	}
	return len(ptr.LoTEQualifiers) == 0 || !strings.Contains(strings.ToLower(ptr.LoTEQualifiers[0].MimeType), "json")
}

// classicTrustedStatuses are the TS 119 612 service status names (last path
// segment of the Svcstatus URI) that confer trust. Every other status
// (withdrawn, deprecatedatnationallevel, supervisionincessation,
// accreditationceased, accreditationrevoked, ...) means the service is not
// currently trusted. The registry's rule for native LoTEs, "skip withdrawn",
// would wrongly trust most of those, so classic lists are filtered with this
// set when they are converted (see dropUntrustedClassicEntities).
var classicTrustedStatuses = map[string]bool{
	"granted":                   true,
	"recognisedatnationallevel": true,
	"accredited":                true,
	"undersupervision":          true,
	"setbynationallaw":          true,
}

// classicStatusTrusted reports whether a TS 119 612 service status URI confers trust.
func classicStatusTrusted(status string) bool {
	// Real TSLs use both ".../Svcstatus/granted" and ".../Svcstatus/granted/".
	status = strings.TrimRight(status, "/")
	name := status[strings.LastIndex(status, "/")+1:]
	return classicTrustedStatuses[strings.ToLower(name)]
}

// loadClassicTSL loads the classic TSL at location and converts it to a LoTE.
// With roots non-nil the TSL is fetched once, its XMLDSig verified against
// roots, and the verified bytes are what gets parsed. With roots nil it is
// loaded unverified.
func (r *Registry) loadClassicTSL(location string, roots *x509.CertPool) (*etsi119602.ListOfTrustedEntities, error) {
	var tsl *etsi119612.TSL
	var err error
	if roots != nil {
		tsl, err = r.fetchVerifiedTSL(location, roots)
	} else {
		tsl, err = r.fetchUnverifiedTSL(location)
	}
	if err != nil {
		return nil, err
	}
	lote := etsi119602.FromTSL(tsl)
	// FromTSL copies the document's own TSLType into LoTEType, and the index
	// selects the classic status rules from that value. A target reached
	// through a classic pointer must therefore declare a classic type itself,
	// or it could opt into the permissive LoTE status rule.
	if declared := lote.ListAndSchemeInformation.LoTEType; !IsClassicTSLSchemeType(declared) {
		return nil, fmt.Errorf("classic TSL pointer target %s declares TSLType %q, which is not a TS 119 612 TSL type", location, declared)
	}
	dropUntrustedClassicEntities(lote)
	qualifyClassicEntityIDs(lote, location)
	if len(lote.ListAndSchemeInformation.PointersToOtherLoTE) > 0 && r.config.Logger != nil {
		r.config.Logger.Warn("classic TSL has pointers to other TSLs; they are not followed",
			slog.String("location", location))
	}
	return lote, nil
}

// fetchUnverifiedTSL loads a TSL without dereferencing its own pointers.
func (r *Registry) fetchUnverifiedTSL(location string) (*etsi119612.TSL, error) {
	opts := etsi119612.DefaultTSLFetchOptions
	opts.MaxDereferenceDepth = 0
	opts.CryptoExt = r.config.CryptoExt
	if r.config.FetchTimeout > 0 {
		opts.Timeout = r.config.FetchTimeout
	}
	src := location
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") && !strings.HasPrefix(src, "file://") {
		src = "file://" + src // the TSL fetcher only reads local files via file://
	}
	tsl, err := etsi119612.FetchTSLWithOptions(src, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch classic TSL from %s: %w", location, err)
	}
	return tsl, nil
}

// fetchVerifiedTSL fetches location once, verifies the XMLDSig over exactly
// those bytes and parses the verified content (never the raw bytes).
func (r *Registry) fetchVerifiedTSL(location string, roots *x509.CertPool) (*etsi119612.TSL, error) {
	raw, err := fetchRawSource(location, r.config.FetchTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch classic TSL from %s: %w", location, err)
	}
	signer, verified, err := verifyTSLSignature(context.Background(), raw, roots, r.now())
	if err != nil {
		return nil, fmt.Errorf("classic TSL signature verification failed for %s: %w", location, err)
	}
	tsl := &etsi119612.TSL{Source: location, Signed: true, Signer: *signer}
	if err := xml.Unmarshal(verified, &tsl.StatusList); err != nil {
		return nil, fmt.Errorf("failed to parse verified classic TSL from %s: %w", location, err)
	}
	tsl.CleanCerts()
	if r.config.Logger != nil {
		r.config.Logger.Info("classic TSL XMLDSig verified",
			slog.String("source", location),
			slog.String("signer", signer.Subject.CommonName))
	}
	return tsl, nil
}

// dropUntrustedClassicEntities removes, from a list converted from a classic
// TSL, every service whose status does not confer trust, and every entity left
// without a service. The filtering is done here, on lists known to come from
// classic XML, rather than in the index: a native JSON LoTE may declare a
// classic TSLType, and the TS 119 612 status vocabulary must not be applied to
// it. Dropping the whole entity (not only its keys) matters because presence
// in a non-Pub-EAA list means trusted.
func dropUntrustedClassicEntities(lote *etsi119602.ListOfTrustedEntities) {
	kept := lote.TrustedEntitiesList[:0]
	for _, ent := range lote.TrustedEntitiesList {
		svcs := ent.TrustedEntityServices[:0:0]
		for _, svc := range ent.TrustedEntityServices {
			if classicStatusTrusted(svc.ServiceInformation.ServiceStatus) {
				svcs = append(svcs, svc)
			}
		}
		if len(svcs) > 0 {
			ent.TrustedEntityServices = svcs
			kept = append(kept, ent)
		}
	}
	lote.TrustedEntitiesList = kept
}

// qualifyClassicEntityIDs makes the synthetic entity IDs produced by FromTSL
// unique across lists. FromTSL derives them from service type and position
// ("<svctype>#tsp0-svc0"), so two classic TSLs would otherwise collide in the
// registry's byID index and one list's entities would silently replace the
// other's.
func qualifyClassicEntityIDs(lote *etsi119602.ListOfTrustedEntities, location string) {
	for i := range lote.TrustedEntitiesList {
		uris := lote.TrustedEntitiesList[i].TrustedEntityInformation.TEInformationURI
		if len(uris) == 0 {
			continue
		}
		id := uris[0].URIValue
		if h := strings.LastIndex(id, "#"); h >= 0 {
			id = id[h:]
		} else {
			id = "#" + id
		}
		uris[0].URIValue = location + id
	}
}

// verifyTSLSignature verifies the enveloped XMLDSig of a classic TSL and
// returns the signer certificate and the verified document bytes. Callers MUST
// parse the returned bytes, not raw.
//
// Why this is not simply dsig.VerifyXMLSignature(raw, anchors): the g119612
// verifier takes a flat list of exact signer certificates and only accepts a
// signature whose embedded certificate is byte-equal to one of them. It does no
// chain building, and an x509.CertPool cannot be enumerated into that list. The
// trust_anchor_bundle holds CA roots, so go-trust does the chain validation
// itself and then hands the chain-validated signer to the library as the sole
// trusted certificate. The library then checks the signature value, that the
// signed Reference covers the document root (enveloped-signature transform
// applied to the root), the digest, and the signer's validity period, and
// returns the signed content.
//
// KeyInfo/X509Data is an unordered set, so every embedded certificate is tried
// as the signer in turn (the others serve as candidate intermediates); the
// signer is the one that chains to roots and whose key verifies the signature.
// The library reads the first KeyInfo certificate, so the verified copy of the
// document carries only the candidate. KeyInfo is not covered by the signed
// reference, so this does not change what is verified.
//
// go-trust additionally enforces, fail closed:
//   - exactly one ds:Signature in the whole document, and it is a direct child
//     of the root element (no signature hidden in an extension or wrapper
//     element, no second signature the library might pick instead);
//   - a signer certificate chain that validates to roots at now;
//   - no SHA-1 signature or digest algorithms.
//
// Not checked: revocation, XAdES SignedProperties/signing time. Certificates
// are parsed with crypto/x509, so signers needing the configured CryptoExt
// (e.g. brainpool) are not supported on this path, as on the JWS path.
func verifyTSLSignature(_ context.Context, raw []byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, []byte, error) {
	if roots == nil {
		return nil, nil, errors.New("lote: no trust anchors available for XMLDSig verification")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, nil, fmt.Errorf("lote: parsing TSL XML: %w", err)
	}
	sig, err := soleRootSignature(doc)
	if err != nil {
		return nil, nil, err
	}
	if err := rejectSHA1(sig); err != nil {
		return nil, nil, err
	}
	if err := checkReferences(sig); err != nil {
		return nil, nil, err
	}
	certs, err := signatureKeyInfoCerts(sig)
	if err != nil {
		return nil, nil, err
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs {
		intermediates.AddCert(c)
	}
	var errs []error
	for _, cand := range certs {
		payload, err := verifyWithSigner(raw, cand, intermediates, roots, now)
		if err == nil {
			return cand, payload, nil
		}
		errs = append(errs, err)
	}
	return nil, nil, errors.Join(errs...)
}

// verifyWithSigner treats cand as the signer: it validates its chain to roots
// (intermediates holds the KeyInfo certificates, including cand itself, which
// is harmless), then verifies the document's XMLDSig with it as the only
// trusted certificate. It returns the serialised verified content.
func verifyWithSigner(raw []byte, cand *x509.Certificate, intermediates, roots *x509.CertPool, now time.Time) ([]byte, error) {
	if _, err := cand.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("lote: TSL signer certificate chain validation failed: %w", err)
	}
	payload, err := verifyEnvelopedSignature(raw, cand)
	if err != nil {
		return nil, fmt.Errorf("lote: %w", err)
	}
	return payload, nil
}

// verifyEnvelopedSignature verifies the enveloped XMLDSig of xmlData with cert as the
// signing key, and returns the verified content: the
// referenced element that is the document's root, serialised after the
// signature's transforms (so without the signature). Only that content may be
// used; the rest of xmlData is not covered by the signature.
//
// signedxml is used, as by g119612 when it loads TSLs, instead of
// dsig.VerifyXMLSignature (goxmldsig): that resolves the signed element
// through an attribute named "ID" only, while published TS 119 612 and
// TS 119 602 XML carry it in "Id" on the root, so no published list verifies
// with it, and it refuses documents of more than 1000 elements.
func verifyEnvelopedSignature(xmlData []byte, cert *x509.Certificate) (payload []byte, err error) {
	// signedxml builds element paths from attacker-controlled values; a panic
	// there must be a rejected list, never a crashed refresh.
	defer func() {
		if r := recover(); r != nil {
			payload, err = nil, fmt.Errorf("signature verification panicked: %v", r)
		}
	}()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlData); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, errors.New("XML document has no root element")
	}
	// The reference target is "Id" in published lists, "ID" in lists made by
	// goxmldsig-based signers; the root decides, no other spelling is accepted.
	idAttr := "Id"
	if root.SelectAttr("ID") != nil {
		idAttr = "ID"
	}
	rootID := root.SelectAttrValue(idAttr, "") // empty when the signature references the whole document (URI="")
	v, err := signedxml.NewValidator(string(xmlData))
	if err != nil {
		return nil, err
	}
	v.SetReferenceIDAttribute(idAttr)
	// Pin the signature key to the validated signer: signedxml would otherwise
	// try every certificate found in the document. KeyInfo is left as signed,
	// since some publishers sign it.
	v.Certificates = []x509.Certificate{*cert}
	refs, err := v.ValidateReferences()
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	if signer := v.SigningCert(); !signer.Equal(cert) {
		return nil, errors.New("signature was not made with the validated signer certificate")
	}
	for _, ref := range refs {
		rd := etree.NewDocument()
		if err := rd.ReadFromString(ref); err != nil {
			continue
		}
		if r := rd.Root(); r != nil && r.Tag == root.Tag && r.Space == root.Space && r.SelectAttrValue(idAttr, "") == rootID {
			return []byte(ref), nil
		}
	}
	return nil, errors.New("signature does not cover the root element")
}

func isDSig(e *etree.Element, tag string) bool {
	return e.Tag == tag && e.NamespaceURI() == xmlDSigNS
}

// soleRootSignature returns the document's only ds:Signature, requiring it to
// be a direct child of the root element.
func soleRootSignature(doc *etree.Document) (*etree.Element, error) {
	root := doc.Root()
	if root == nil {
		return nil, errors.New("lote: TSL document has no root element")
	}
	var all []*etree.Element
	var walk func(e *etree.Element)
	walk = func(e *etree.Element) {
		for _, c := range e.ChildElements() {
			if isDSig(c, "Signature") {
				all = append(all, c)
			}
			walk(c)
		}
	}
	walk(root)
	switch {
	case len(all) == 0:
		return nil, errors.New("lote: TSL is not signed (no ds:Signature)")
	case len(all) > 1:
		return nil, fmt.Errorf("lote: TSL has %d ds:Signature elements, exactly one is required", len(all))
	case all[0].Parent() != root:
		return nil, errors.New("lote: TSL ds:Signature is not a direct child of the document root")
	}
	return all[0], nil
}

// rejectSHA1 refuses SHA-1 signature and digest methods.
func rejectSHA1(sig *etree.Element) error {
	for _, tag := range []string{"SignatureMethod", "DigestMethod"} {
		for _, e := range sig.FindElements(".//" + tag) {
			if !isDSig(e, tag) {
				continue
			}
			if alg := e.SelectAttrValue("Algorithm", ""); strings.Contains(strings.ToLower(alg), "sha1") {
				return fmt.Errorf("lote: TSL signature uses SHA-1 (%s)", alg)
			}
		}
	}
	return nil
}

// allowedDigestMethods are the reference digest algorithms accepted: SHA-2
// only. signedxml would also accept MD5, which must never vouch for content.
var allowedDigestMethods = map[string]bool{
	"http://www.w3.org/2001/04/xmlenc#sha256":       true,
	"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
	"http://www.w3.org/2001/04/xmlenc#sha512":       true,
}

// xmlIDRef matches the same-document references accepted: an NCName-shaped
// identifier. Anything else (quotes, brackets, slashes) could be spliced into
// the element path signedxml builds from the URI, so it is refused before the
// library sees it.
var xmlIDRef = regexp.MustCompile(`^#[A-Za-z_][A-Za-z0-9._-]*$`)

// maxSignatureReferences bounds the References in a signature. signedxml
// copies the whole document per reference and keeps the results before the
// signature value is checked, so an unbounded count is a resource-exhaustion
// lever for anyone who can alter the list. Published lists carry two (the
// document and, with XAdES, its SignedProperties).
const maxSignatureReferences = 8

// checkReferences vets the signature's SignedInfo before signedxml runs.
// signedxml finds SignedInfo, Reference and DigestMethod by local name, so
// this does too: an element in another namespace cannot hide from the guard.
// There must be exactly one SignedInfo; at most maxSignatureReferences
// References; every Reference in the XMLDSig namespace, with a URI of "" or a
// plain same-document "#id", and exactly one DigestMethod that is an allowed
// SHA-2 method.
func checkReferences(sig *etree.Element) error {
	var signedInfo *etree.Element
	for _, c := range sig.ChildElements() {
		if c.Tag != "SignedInfo" {
			continue
		}
		if signedInfo != nil {
			return errors.New("lote: TSL signature has more than one SignedInfo")
		}
		signedInfo = c
	}
	if signedInfo == nil || !isDSig(signedInfo, "SignedInfo") {
		return errors.New("lote: TSL signature has no ds:SignedInfo")
	}
	refs := 0
	for _, ref := range signedInfo.ChildElements() {
		if ref.Tag != "Reference" {
			continue
		}
		if refs++; refs > maxSignatureReferences {
			return fmt.Errorf("lote: TSL signature has more than %d references", maxSignatureReferences)
		}
		if !isDSig(ref, "Reference") {
			return errors.New("lote: TSL signature has a Reference outside the XMLDSig namespace")
		}
		if uri := ref.SelectAttrValue("URI", ""); uri != "" && !xmlIDRef.MatchString(uri) {
			return fmt.Errorf("lote: TSL signature reference URI %q is not a same-document #id", uri)
		}
		var dm *etree.Element
		for _, c := range ref.ChildElements() {
			if c.Tag != "DigestMethod" {
				continue
			}
			if dm != nil {
				return errors.New("lote: TSL signature reference has more than one DigestMethod")
			}
			dm = c
		}
		if dm == nil || !isDSig(dm, "DigestMethod") {
			return errors.New("lote: TSL signature reference needs exactly one ds:DigestMethod")
		}
		if alg := dm.SelectAttrValue("Algorithm", ""); !allowedDigestMethods[alg] {
			return fmt.Errorf("lote: TSL signature digest method %q is not allowed (SHA-2 only)", alg)
		}
	}
	if refs == 0 {
		return errors.New("lote: TSL signature has no references")
	}
	return nil
}

// signatureKeyInfoCerts returns every certificate in KeyInfo/X509Data, in
// document order.
func signatureKeyInfoCerts(sig *etree.Element) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, e := range sig.FindElements("./KeyInfo/X509Data/X509Certificate") {
		if !isDSig(e, "X509Certificate") {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(e.Text()), ""))
		if err != nil {
			return nil, fmt.Errorf("lote: decoding TSL signer certificate: %w", err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("lote: parsing TSL signer chain: %w", err)
		}
		certs = append(certs, c)
		if len(certs) > maxKeyInfoCerts {
			return nil, fmt.Errorf("lote: TSL signature KeyInfo carries more than %d certificates", maxKeyInfoCerts)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("lote: TSL signature has no X509Certificate in KeyInfo")
	}
	return certs, nil
}
