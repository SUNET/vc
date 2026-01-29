package apiv1

import (
	"vc/pkg/openid4vci"
	"vc/pkg/openid4vp"
)

// deriveVPFormatsFromMetadata derives VP formats configuration from issuer metadata.
// This extracts format and algorithm information from CredentialConfigurationsSupported
// to build the VP formats structure needed for OpenID4VP authorization requests.
func deriveVPFormatsFromMetadata(metadata *openid4vci.CredentialIssuerMetadataParameters) *openid4vp.VPFormatsSupported {
	result := &openid4vp.VPFormatsSupported{}

	if metadata == nil || metadata.CredentialConfigurationsSupported == nil {
		return result
	}

	// Track which formats we've seen to aggregate algorithms
	sdjtAlgs := make(map[string]bool)
	kbjwtAlgs := make(map[string]bool)
	mdocAlgs := make(map[int]bool)

	// Iterate through all credential configurations
	for _, config := range metadata.CredentialConfigurationsSupported {
		format := config.Format
		if format == "" {
			continue
		}

		// Handle SD-JWT formats (dc+sd-jwt, vc+sd-jwt)
		if format == "dc+sd-jwt" || format == "vc+sd-jwt" {
			// SD-JWT signing algorithms
			for _, alg := range config.CredentialSigningAlgValuesSupported {
				if algStr, ok := alg.(string); ok {
					sdjtAlgs[algStr] = true
				}
			}

			// Key binding algorithms (from proof_types_supported)
			if jwtProof, ok := config.ProofTypesSupported["jwt"]; ok {
				for _, alg := range jwtProof.ProofSigningAlgValuesSupported {
					kbjwtAlgs[alg] = true
				}
			}
		}

		// Handle mso_mdoc format
		if format == "mso_mdoc" {
			// mso_mdoc uses integer COSE algorithm identifiers
			for _, alg := range config.CredentialSigningAlgValuesSupported {
				// COSE identifiers are integers (e.g., -7 for ES256)
				if algInt, ok := alg.(float64); ok {
					mdocAlgs[int(algInt)] = true
				}
			}
		}
	}

	// Build SD-JWT format if we found any algorithms
	if len(sdjtAlgs) > 0 || len(kbjwtAlgs) > 0 {
		result.SDJWT = &openid4vp.SDJWTVCFormat{}
		if len(sdjtAlgs) > 0 {
			result.SDJWT.SDJWTAlgValues = make([]string, 0, len(sdjtAlgs))
			for alg := range sdjtAlgs {
				result.SDJWT.SDJWTAlgValues = append(result.SDJWT.SDJWTAlgValues, alg)
			}
		}
		if len(kbjwtAlgs) > 0 {
			result.SDJWT.KBJWTAlgValues = make([]string, 0, len(kbjwtAlgs))
			for alg := range kbjwtAlgs {
				result.SDJWT.KBJWTAlgValues = append(result.SDJWT.KBJWTAlgValues, alg)
			}
		}
	}

	// Build mso_mdoc format if we found any algorithms
	if len(mdocAlgs) > 0 {
		result.MsoMdoc = &openid4vp.MsoMdocFormat{}
		result.MsoMdoc.IssuerAuthAlgValues = make([]int, 0, len(mdocAlgs))
		for alg := range mdocAlgs {
			result.MsoMdoc.IssuerAuthAlgValues = append(result.MsoMdoc.IssuerAuthAlgValues, alg)
		}
		// DeviceAuth typically uses the same algorithms
		result.MsoMdoc.DeviceAuthAlgValues = result.MsoMdoc.IssuerAuthAlgValues
	}

	return result
}
