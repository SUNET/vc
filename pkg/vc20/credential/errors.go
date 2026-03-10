package credential

import "errors"

// Validation errors
var (
	ErrMissingContext               = errors.New("@context is required")
	ErrInvalidBaseContext           = errors.New("first @context must be https://www.w3.org/ns/credentials/v2")
	ErrInvalidContext               = errors.New("invalid @context")
	ErrMissingType                  = errors.New("type is required")
	ErrInvalidType                  = errors.New("invalid type")
	ErrMissingVCType                = errors.New("type must include 'VerifiableCredential'")
	ErrInvalidID                    = errors.New("invalid id")
	ErrMissingIssuer                = errors.New("issuer is required")
	ErrInvalidIssuerID              = errors.New("issuer id must be a valid URL")
	ErrMissingValidFrom             = errors.New("validFrom is required")
	ErrInvalidValidFrom             = errors.New("validFrom must be a valid dateTimeStamp")
	ErrInvalidValidUntil            = errors.New("validUntil must be a valid dateTimeStamp")
	ErrValidUntilBeforeValidFrom    = errors.New("validUntil must be after validFrom")
	ErrMissingValidUntil            = errors.New("validUntil not specified")
	ErrMissingCredentialSubject     = errors.New("credentialSubject is required")
	ErrEmptyCredentialSubject       = errors.New("credentialSubject cannot be empty")
	ErrInvalidIssuerFormat          = errors.New("invalid issuer format")
	ErrInvalidProofFormat           = errors.New("invalid proof format")
	ErrMissingProof                 = errors.New("proof is required")
	ErrInvalidCredentialStatusType  = errors.New("credentialStatus must have a type")
	ErrInvalidCredentialSchemaType  = errors.New("credentialSchema must have a type")
	ErrInvalidRefreshServiceType    = errors.New("refreshService must have a type")
	ErrInvalidTermsOfUseType        = errors.New("termsOfUse must have a type")
	ErrInvalidEvidenceType          = errors.New("evidence must have a type")
	ErrInvalidRelatedResource       = errors.New("invalid relatedResource")
	ErrInvalidLanguageValueObject   = errors.New("invalid language value object")
	ErrReservedTypeRedefinition     = errors.New("reserved type cannot be redefined")
	ErrInvalidIssuerDescription     = errors.New("issuer description cannot have extra properties")
	ErrInvalidCredentialDescription = errors.New("credential description cannot have extra properties")
	ErrInvalidNameValueObject       = errors.New("name must be a string or language value object")
	ErrInvalidIssuerName            = errors.New("issuer name must be a string or language value object")
	ErrContextNotArray              = errors.New("@context must be an array")
	ErrTypeNotArray                 = errors.New("type must be an array")
	ErrInvalidTypeValue             = errors.New("type value must be a valid term or URL")
	ErrInvalidIDFormat              = errors.New("id must be a valid URL")
)

// Context errors
var (
	ErrContextNotFound     = errors.New("context document not found")
	ErrContextHashMismatch = errors.New("context hash does not match expected value")
	ErrInvalidContextURL   = errors.New("invalid context URL")
)

// Cryptographic errors
var (
	ErrUnsupportedCryptosuite = errors.New("unsupported cryptographic suite")
	ErrInvalidSignature       = errors.New("invalid signature")
	ErrInvalidProofValue      = errors.New("invalid proof value")
	ErrInvalidKeyFormat       = errors.New("invalid key format")
	ErrSigningFailed          = errors.New("signing failed")
	ErrVerificationFailed     = errors.New("verification failed")
)

// RDF errors
var (
	ErrRDFCanonicalizationFailed = errors.New("RDF canonicalization failed")
	ErrInvalidRDFDataset         = errors.New("invalid RDF dataset")
	ErrBlankNodeRandomization    = errors.New("blank node randomization failed")
)

// Selective disclosure errors
var (
	ErrInvalidJSONPointer = errors.New("invalid JSON pointer")
	ErrMandatoryPointer   = errors.New("mandatory pointer cannot be disclosed selectively")
	ErrInvalidSelection   = errors.New("invalid selection")
	ErrDerivedProofFailed = errors.New("derived proof creation failed")
)
