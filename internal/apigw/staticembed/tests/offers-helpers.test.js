// Unit tests for the credential-offer page helpers. Runs under Node's
// built-in test runner (`node --test`, see the Makefile's test-js target) —
// no extra dependencies. Covers pure logic only; the Alpine component in
// offers.js is not exercised here.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
    credentialOfferData,
    issuanceResult,
    OID4VCI_PROTOCOL,
} from "../offers-helpers.js";

describe("OID4VCI_PROTOCOL", () => {
    it("is the OpenID4VCI 1.0 DC API protocol identifier", () => {
        assert.equal(OID4VCI_PROTOCOL, "openid4vci-v1");
    });
});

// offers.js is not exercised here (no Alpine, no DOM), so these are source
// assertions rather than behavioural ones. They guard two choices that are
// invisible from the helpers alone and expensive to get wrong.
describe("offers.js DC API wiring", () => {
    const source = readFileSync(new URL("../offers.js", import.meta.url), "utf8");

    it("does not claim the user cancelled on NotAllowedError", () => {
        // isUserCancel() is true for EVERY NotAllowedError, but the polyfill
        // raises that for a blocked popup, for no provider supporting the
        // protocol, and for any error the wallet itself reports. Telling the
        // operator they cancelled sends them looking in the wrong place.
        // Matched on the import rather than on any mention, so the comment
        // in offers.js explaining why it is not used stays allowed.
        assert.equal(
            /import\s*\{[^}]*\bisUserCancel\b[^}]*\}/.test(source),
            false,
            "offers.js must not branch on isUserCancel(): it cannot distinguish a " +
                "user who closed the wallet from a popup the browser blocked. Use the " +
                "library's own NotAllowedError message, which hedges correctly.",
        );
    });

    it("installs the combined bundle, not the standalone polyfill", () => {
        // The library's separate polyfill and web-wallets bundles each inline
        // their own wallet registry, so a wallet registered through one is
        // invisible to the other's create() shim (sirosfoundation/dc-api#23).
        // Only the combined /full bundle carries both in one module instance,
        // and installing the wrong one fails silently: the button renders or
        // hides correctly, and create() rejects with a provider present.
        assert.match(source, /from "\.\/dc-api-full\.js"/);
        assert.equal(
            /dc-api-polyfill\.js/.test(source),
            false,
            "offers.js must install the combined bundle: the standalone polyfill " +
                "cannot see wallets registered through window.DigitalWallets.",
        );
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

// navigator.credentials.create() may resolve with no credential at all - the
// W3C API allows it and the vendored polyfill hands the native result back
// unchanged. The page used to discard the result and announce a handover
// regardless, stranding the operator on a page that looked finished.
describe("issuanceResult", () => {
    it("treats null as nothing having started", () => {
        assert.deepEqual(issuanceResult(null), { pending: true });
    });

    it("treats undefined as nothing having started", () => {
        assert.deepEqual(issuanceResult(undefined), { pending: true });
    });

    it("reports a handover for a real credential", () => {
        const out = issuanceResult({ type: "digital", protocol: "openid4vci-v1", data: {} });
        assert.equal("pending" in out, false);
        assert.match(out.status, /wallet/i);
    });
});
