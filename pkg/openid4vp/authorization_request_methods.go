package openid4vp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
)

type PresentationDefinitionParameter struct {
	// ID The Presentation Definition MUST contain an id property. The value of this property MUST be a string.
	// The string SHOULD provide a unique ID for the desired context.
	ID string `json:"id" bson:"id" validate:"required"`

	// Name The Presentation Definition MAY contain a name property. If present, its value SHOULD be a
	// human-friendly string intended to constitute a distinctive designation of the Presentation Definition.
	Name string `json:"name,omitempty" bson:"name,omitempty"`

	// Purpose The Presentation Definition MAY contain a purpose property. If present, its value MUST be a
	// string that describes the purpose for which the Presentation Definition's inputs are being used for.
	Purpose string `json:"purpose,omitempty" bson:"purpose,omitempty"`

	// InputDescriptors The Presentation Definition MUST contain an input_descriptors property.
	// Its value MUST be an array of Input Descriptor Objects.
	InputDescriptors []InputDescriptor `json:"input_descriptors" bson:"input_descriptors" validate:"required,dive"`

	// SubmissionRequirements The Presentation Definition MAY contain a submission_requirements property.
	// If present, its value MUST be an array of Submission Requirement Objects.
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty" bson:"submission_requirements,omitempty" validate:"omitempty,dive"`

	// Format The Presentation Definition MAY contain a format property. If present, its value MUST be an object
	// with one or more properties matching the registered Claim Format Designations.
	Format map[string]Format `json:"format,omitempty" bson:"format,omitempty"`
}

// Sign creates a signed JWT representation of the RequestObject according to OpenID4VP specification.
// The JWT typ header is set to "oauth-authz-req+jwt" as required by OpenID4VP Section 5.2.
// Uses pki.Signer interface which supports both software keys and HSM.
//
// Parameters:
//   - ctx: Context for signing operations
//   - signer: The pki.Signer for signing (supports both software and HSM keys)
//   - x5c: Optional X.509 certificate chain for key verification
//
// Returns the signed JWT string or an error if signing fails.
func (r *RequestObject) Sign(ctx context.Context, signer pki.Signer, x5c []string) (string, error) {
	if r == nil {
		return "", fmt.Errorf("request object cannot be nil")
	}
	if signer == nil {
		return "", fmt.Errorf("signer cannot be nil")
	}

	// Build JWT header with required typ claim per OpenID4VP Section 5.2
	header := jwt.MapClaims{
		"typ": "oauth-authz-req+jwt",
	}

	// Only include x5c if provided and non-empty
	if len(x5c) > 0 {
		header["x5c"] = x5c
	}

	// Convert RequestObject to JWT claims
	data, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request object: %w", err)
	}

	claims := jwt.MapClaims{}
	if err := json.Unmarshal(data, &claims); err != nil {
		return "", fmt.Errorf("failed to create JWT claims: %w", err)
	}

	// Sign using jose.MakeJWT which handles pki.Signer
	signedJWT, err := jose.MakeJWT(ctx, header, claims, signer)
	if err != nil {
		return "", err
	}

	return signedJWT, nil
}
