// Pure helpers for the credential-offer page. Kept in a separate module so
// they can be unit-tested under Node without pulling in Alpine, valibot, or
// the DOM (same arrangement as consent-helpers.js).

import { OID4VCI_PROTOCOLS, isProtocolAllowed } from "./dc-api.js";

/** The OpenID4VCI 1.0 DC API protocol identifier. */
export const OID4VCI_PROTOCOL = OID4VCI_PROTOCOLS.V1;

/**
 * Can an openid4vci-v1 issuance request actually be fulfilled on this device?
 *
 * This is deliberately the ONLY place the question is asked, and it is the
 * only thing that decides whether the same-device button renders. It is not
 * "does the browser have the DC API" (isDCAPIAvailable), which is a weaker
 * claim: a browser can expose DigitalCredential and still have nothing that
 * can take an issuance request, in which case navigator.credentials.create()
 * rejects with NotAllowedError — a worse outcome than the QR code that
 * already works.
 *
 * TODAY THIS RETURNS FALSE EVERYWHERE, AND THE BUTTON IS DELIBERATELY
 * DORMANT. Both of its clauses are unreachable on a shipping browser:
 *
 *   1. No shipping user agent natively allows `openid4vci-v1`, so
 *      DigitalCredential.userAgentAllowsProtocol (via the library's
 *      isProtocolAllowed) says no.
 *   2. Nothing defines `window.DigitalWallets` on this page. That global
 *      comes from the library's web-wallets bundle, and vendoring that
 *      bundle alongside dc-api-polyfill.js would NOT connect the two:
 *      each bundle inlines its own copy of the wallet registry and its own
 *      installPolyfill, so a wallet registered through one is invisible to
 *      the create() shim in the other. See sirosfoundation/dc-api#23 — this
 *      needs a single combined bundle (one module instance) from the
 *      library before the clause can ever be true.
 *
 * The polyfill's own registerWallet() is the one path that is coherent
 * today: a wallet registered through the very module instance this page
 * installs is both reported here and found by that instance's create().
 * Nothing on this page calls it.
 *
 * Do not "fix" this by making it return true — a true that leads to a
 * create() which rejects is exactly what the gate exists to prevent.
 *
 * Replace the whole function with isIssuanceAvailable() from
 * @sirosfoundation/dc-api once the library ships it (sirosfoundation/dc-api#20)
 * on top of the combined bundle (#23). The predicate belongs in the library,
 * not here.
 *
 * @returns {boolean}
 */
export function isIssuanceAvailable() {
    if (isProtocolAllowed(OID4VCI_PROTOCOL)) {
        return true;
    }

    return globalThis.DigitalWallets?.supportsProtocol?.(OID4VCI_PROTOCOL) === true;
}

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
