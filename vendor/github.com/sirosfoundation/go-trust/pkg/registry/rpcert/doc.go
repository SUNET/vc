// Package rpcert models the certificates that authenticate a Relying Party
// to an EUDI Wallet, and evaluates what those certificates entitle it to.
//
// Two documents are involved, issued by different authorities and answering
// different questions:
//
//   - The access certificate (WRPAC, ETSI TS 119 411-8) is an X.509
//     certificate from an Access CA. It answers "who is this party, and is
//     it allowed to talk to wallets at all". See NewWRPACProfile.
//   - The registration certificate (WRPRC, ETSI TS 119 475) is a signed JWT
//     with media type "rc-wrp+jwt", issued by a national Registrar. It
//     answers "what is this party registered to request, or to provide".
//     See ParseWRPRCClaims.
//
// The two are bound together by the organisation identifier, which must
// appear in both (ARF RPRC_16) - see CheckWRPACWRPRCBinding.
//
// # Three steps, and which one belongs here
//
// Validating a signed object is three separate steps:
//
//  1. Verify the signature.
//  2. Extract the trust information.
//  3. Evaluate that trust information against a policy.
//
// This package owns step three, and offers step two as a convenience for
// the wire formats above. It deliberately does not do step one. There is no
// JWS implementation here and there should not be one: the caller holds the
// protocol context that determines which algorithms, keys and time source
// are acceptable, and a trust registry that silently verified signatures on
// the caller's behalf would be asserting a guarantee it is not positioned to
// make.
//
// A correctly layered caller therefore looks like this:
//
//	// 1. verify - the caller's own JWS library and policy
//	if err := myJOSE.Verify(token, leafPublicKey); err != nil {
//	        return err
//	}
//
//	// 2. extract
//	payload, err := rpcert.ParseWRPRCJWTPayload(token)
//	if err != nil {
//	        return err
//	}
//	ent, err := rpcert.ParseWRPRCClaims(payload)
//	if err != nil {
//	        return err
//	}
//
//	// 3. evaluate
//	if err := rpcert.CheckWRPRCValidityPeriod(ent); err != nil {
//	        return err
//	}
//	if err := rpcert.CheckWRPACWRPRCBinding(orgID, ent); err != nil {
//	        return err
//	}
//	ent.RegistrationStatus = rpcert.StatusRegistered // the caller's decision
//
// ParseWRPRCClaims returns entitlements marked StatusUnknown, so IsValid
// reports false until a caller that has completed steps one and three says
// otherwise. Nothing in this package will mark a document registered on the
// caller's behalf.
//
// JWTRegistrationCertValidator predates this split and conflates all three
// steps - without ever implementing step one. It is deprecated; see its
// documentation.
//
// # What is here
//
// Extraction:
//
//   - ParseWRPRCClaims, ParseWRPRCJWTPayload - WRPRC payload to
//     RPEntitlements, tolerant of both TS 119 475 v1.1.1 and v1.2.1 field
//     spellings.
//   - WRPACProfile.ExtractIdentity - WRPAC certificate to an identity map,
//     including the organisation identifier that binds it to a WRPRC.
//
// Evaluation:
//
//   - RPEntitlements.HasEntitlement, IsEAAProvider, IsAttestationProvider -
//     what role the Registrar granted.
//   - RPEntitlements.ProvidesAttestation - whether an issuer is registered
//     for a given credential format and type.
//   - DetectOverRequest, DCQLPolicyEvaluator - whether a request stays
//     within the registered attribute set.
//   - CheckWRPACWRPRCBinding, CheckWRPRCValidityPeriod - conformance rules
//     that need no network and no keys.
//
// # What is not here
//
// No signature verification and no network access.
//
// Revocation follows the same split. A WRPAC is revoked through a CRL or
// OCSP; a WRPRC through the Token Status List named in its own status
// claim. This package says where to look - CRLDistributionPoints,
// OCSPResponders, RPEntitlements.StatusReference - and decides what an
// answer means, through RevocationMode.Evaluate. It does not fetch: the
// caller supplies a StatusListChecker or CertRevocationChecker, the same
// way key resolvers are injected elsewhere here.
//
// The distinction that matters in that decision is between "revoked" and
// "could not determine". An unreachable list is not evidence that a
// certificate is valid, and collapsing the two is how a fetch failure
// quietly becomes a pass - so RevocationUndetermined is its own state, and
// RevocationWarn reports it while still proceeding.
//
// # References
//
//   - ETSI TS 119 475 - RP attributes supporting Wallet user's authorisation
//     decisions. v1.1.1 and v1.2.1 differ on the wire; both are accepted.
//   - ETSI TS 119 411-8 v1.1.1 - Access Certificate Policy for EUDI Wallet
//     Relying Parties.
//   - EN 319 412-3 clause 4.2.1 - organizationIdentifier (OID 2.5.4.97) for
//     legal persons.
//   - CIR (EU) 2025/848 Annex I point 12 - the entitlement list.
//   - EUDI ARF RPRC_16 to RPRC_21 - registration certificate validation.
package rpcert
