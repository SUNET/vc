// Pure helpers for the credential-offer page. Kept in a separate module so
// they can be unit-tested under Node without pulling in Alpine, valibot, or
// the DOM (same arrangement as consent-helpers.js).

/**
 * The OpenID4VCI 1.0 DC API protocol identifier.
 *
 * Duplicated from the library rather than imported, so this module stays free
 * of browser-only dependencies and can be unit-tested under plain node. It is
 * a protocol identifier fixed by the DC API spec, not a moving part.
 */
export const OID4VCI_PROTOCOL = "openid4vci-v1";

/**
 * Decode the server's `credential_offer=...` query string into the Credential
 * Offer object that an openid4vci-v1 DC API request carries as its `data`.
 *
 * The server hands the page one offer as a query string because that is the
 * form every other rendering (QR, opaque deep link, per-wallet deep links)
 * needs; only the DC API path wants it as an object.
 *
 * @param {string} offer  the `credential_offer=<urlencoded json>` query string
 * @returns {object}      the Credential Offer object
 */
export function credentialOfferData(offer) {
    if (typeof offer !== "string" || offer === "") {
        throw new Error("credential offer is empty");
    }

    const raw = new URLSearchParams(offer).get("credential_offer");
    if (!raw) {
        throw new Error("credential offer has no credential_offer parameter");
    }

    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("credential_offer is not a JSON object");
    }

    return parsed;
}

/**
 * Interpret what navigator.credentials.create() resolved with.
 *
 * The call can resolve with NO credential - the W3C API allows it, and the
 * vendored polyfill hands the native result straight back, which may be null.
 * That is not success: nothing was issued, and the page must not tell the
 * operator their wallet has taken over when it has not. It is not an error
 * either, since nothing failed; the QR is still there and still works.
 *
 * @param {unknown} result  whatever create() resolved with
 * @returns {{ status: string } | { pending: true }}
 *   status to show on a real handover, pending when nothing came back
 */
export function issuanceResult(result) {
    if (!result) {
        return { pending: true };
    }

    return { status: "Your wallet has taken over the issuance." };
}
