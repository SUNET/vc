// Unit tests for the credential-offer page helpers. Runs under Node's
// built-in test runner (`node --test`, see the Makefile's test-js target) —
// no extra dependencies. Covers pure logic only; the Alpine component in
// offers.js is not exercised here.

import { afterEach, before, describe, it } from "node:test";
import assert from "node:assert/strict";

import {
    credentialOfferData,
    isIssuanceAvailable,
    OID4VCI_PROTOCOL,
} from "../offers-helpers.js";

/** Remove whatever the previous test planted on the global object. */
function clearGlobals() {
    delete globalThis.DigitalCredential;
    delete globalThis.DigitalWallets;
}

describe("OID4VCI_PROTOCOL", () => {
    it("is the OpenID4VCI 1.0 DC API protocol identifier", () => {
        assert.equal(OID4VCI_PROTOCOL, "openid4vci-v1");
    });
});

describe("isIssuanceAvailable", () => {
    afterEach(clearGlobals);

    it("is false on a browser with neither the DC API nor a registered web wallet", () => {
        assert.equal(isIssuanceAvailable(), false);
    });

    it("is true when the native user agent allows openid4vci-v1", () => {
        globalThis.DigitalCredential = {
            userAgentAllowsProtocol: (protocol) => protocol === "openid4vci-v1",
        };
        assert.equal(isIssuanceAvailable(), true);
    });

    // The whole point of the predicate: DigitalCredential being defined is
    // NOT the question. A browser that has the DC API but refuses the
    // issuance protocol must not get the button.
    it("is false when the DC API exists but refuses openid4vci-v1", () => {
        globalThis.DigitalCredential = {
            userAgentAllowsProtocol: (protocol) => protocol === "openid4vp-v1-signed",
        };
        assert.equal(isIssuanceAvailable(), false);
    });

    it("is false when the DC API exists without userAgentAllowsProtocol", () => {
        globalThis.DigitalCredential = {};
        assert.equal(isIssuanceAvailable(), false);
    });

    it("is true when a web wallet registered with the polyfill supports openid4vci-v1", () => {
        globalThis.DigitalWallets = {
            supportsProtocol: (protocol) => protocol === "openid4vci-v1",
        };
        assert.equal(isIssuanceAvailable(), true);
    });

    it("is false when the registered web wallets support only presentation", () => {
        globalThis.DigitalWallets = {
            supportsProtocol: (protocol) => protocol === "openid4vp-v1-signed",
        };
        assert.equal(isIssuanceAvailable(), false);
    });

    it("is false when DigitalWallets exists without supportsProtocol", () => {
        globalThis.DigitalWallets = {};
        assert.equal(isIssuanceAvailable(), false);
    });

    it("ignores a truthy non-boolean supportsProtocol result", () => {
        globalThis.DigitalWallets = { supportsProtocol: () => "yes" };
        assert.equal(isIssuanceAvailable(), false);
    });
});

// The same-device button is gated on isIssuanceAvailable() alone, and in the
// state this repo actually ships - the vendored polyfill installed, no wallet
// registered, no native openid4vci-v1 support - it must stay false so the
// button does not render. A create() that rejects with NotAllowedError is
// exactly what the gate exists to prevent, so a change that turns this true
// without also making create() work is a regression, not a fix.
describe("isIssuanceAvailable with the vendored polyfill installed", () => {
    /** @type {typeof import("../dc-api-polyfill.js")} */
    let polyfill;

    before(async () => {
        // installPolyfill() rebinds navigator.credentials.{get,create}.
        Object.defineProperty(globalThis, "navigator", {
            value: { credentials: { get: async () => null, create: async () => null } },
            configurable: true,
            writable: true,
        });
        polyfill = await import("../dc-api-polyfill.js");
    });

    afterEach(() => {
        for (const w of polyfill.getRegisteredWallets()) {
            polyfill.unregisterWallet(w.id);
        }
        if (polyfill.isPolyfillInstalled()) {
            polyfill.uninstallPolyfill();
        }
        clearGlobals();
    });

    it("installs without throwing", () => {
        polyfill.installPolyfill();
        assert.equal(polyfill.isPolyfillInstalled(), true);
    });

    it("does not define window.DigitalWallets", () => {
        polyfill.installPolyfill();
        // That global comes from the library's separate web-wallets bundle,
        // which cannot share this module's registry — sirosfoundation/dc-api#23.
        assert.equal(globalThis.DigitalWallets, undefined);
    });

    it("is false in the state this page ships: installed, nothing registered", () => {
        polyfill.installPolyfill();
        assert.equal(isIssuanceAvailable(), false);
    });

    // Not hardwired false: the polyfill's own registry is coherent, and a
    // wallet registered with this module instance is both reported here and
    // found by this instance's create().
    it("is true for a wallet registered with the same module instance", () => {
        polyfill.installPolyfill();
        polyfill.registerWallet({
            id: "w",
            name: "W",
            url: "https://wallet.example.com/",
            protocols: ["openid4vci-v1"],
        });
        assert.equal(isIssuanceAvailable(), true);
    });

    it("stays false for a wallet that only does presentation", () => {
        polyfill.installPolyfill();
        polyfill.registerWallet({
            id: "w",
            name: "W",
            url: "https://wallet.example.com/",
            protocols: ["openid4vp-v1-signed"],
        });
        assert.equal(isIssuanceAvailable(), false);
    });
});

describe("credentialOfferData", () => {
    const offerObject = {
        credential_issuer: "https://issuer.example.com",
        credential_configuration_ids: ["siros_id"],
        grants: { authorization_code: {} },
    };
    const offerQuery = new URLSearchParams({
        credential_offer: JSON.stringify(offerObject),
    }).toString();

    it("decodes the server's credential_offer query string", () => {
        assert.deepEqual(credentialOfferData(offerQuery), offerObject);
    });

    it("decodes the query string taken from the opaque deep link", () => {
        const uri = `openid-credential-offer://?${offerQuery}`;
        assert.deepEqual(
            credentialOfferData(uri.slice(uri.indexOf("?") + 1)),
            offerObject,
        );
    });

    it("rejects an empty offer", () => {
        assert.throws(() => credentialOfferData(""), /empty/);
        assert.throws(() => credentialOfferData(undefined), /empty/);
    });

    // The by-reference rendering is for the QR only; the DC API path needs
    // the offer by value and must say so rather than send a half-request.
    it("rejects a by-reference offer", () => {
        const byReference = new URLSearchParams({
            credential_offer_uri: "https://issuer.example.com/credential-offer/abc",
        }).toString();
        assert.throws(() => credentialOfferData(byReference), /no credential_offer parameter/);
    });

    it("rejects a credential_offer that is not JSON", () => {
        const bad = new URLSearchParams({ credential_offer: "not json" }).toString();
        assert.throws(() => credentialOfferData(bad), SyntaxError);
    });

    it("rejects a credential_offer that is not a JSON object", () => {
        const array = new URLSearchParams({ credential_offer: "[1,2]" }).toString();
        assert.throws(() => credentialOfferData(array), /not a JSON object/);

        const nullOffer = new URLSearchParams({ credential_offer: "null" }).toString();
        assert.throws(() => credentialOfferData(nullOffer), /not a JSON object/);
    });
});
