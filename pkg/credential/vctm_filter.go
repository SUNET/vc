package credential

import "github.com/SUNET/vc/pkg/sdjwtvc"

// FilterAgainstVCTM returns a copy of doc containing only the top-level keys
// declared by the VCTM's claims paths. Keys the VCTM does not list are
// dropped. This is the anti-PII-leak choke point for credentials whose
// document data is assembled from an external source (e.g. a presented
// credential's own claims): even if upstream forwards more claims than
// intended, only VCTM-declared paths reach the issuer.
//
// A VCTM claim with an empty path is skipped defensively. A first-element
// nil (wildcard over the root) is unusual for SD-JWT VC VCTMs and is
// treated as "declare no top-level key".
//
// This is a top-level filter only. Nested claim declarations (e.g.
// [address, locality]) allow their parent (address) through; sub-key
// selection inside the parent is left to the SD-JWT builder.
func FilterAgainstVCTM(doc map[string]any, vctm *sdjwtvc.VCTM) map[string]any {
	if vctm == nil {
		return map[string]any{}
	}
	allowed := make(map[string]struct{}, len(vctm.Claims))
	for _, c := range vctm.Claims {
		if len(c.Path) == 0 {
			continue
		}
		head := c.Path[0]
		if head == nil {
			continue
		}
		allowed[*head] = struct{}{}
	}
	out := make(map[string]any, len(allowed))
	for k, v := range doc {
		if _, ok := allowed[k]; ok {
			out[k] = v
		}
	}
	return out
}
