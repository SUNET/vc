// Unit tests for the credential-offer page helpers. Runs under Node's
// built-in test runner (`node --test`, see the Makefile's test-js target) —
// no extra dependencies. Covers pure logic only; the Alpine component in
// offers.js is not exercised here.

import { afterEach, describe, it } from "node:test";
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
