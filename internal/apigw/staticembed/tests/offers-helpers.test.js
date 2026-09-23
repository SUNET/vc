// Unit tests for the credential-offer page helpers. Runs under Node's
// built-in test runner (`node --test`, see the Makefile's test-js target) —
// no extra dependencies. Covers pure logic only; the Alpine component in
// offers.js is not exercised here.

import { afterEach, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
    credentialOfferData,
    isIssuanceAvailable,
    issuanceResult,
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
    // These cases are about what the PROBES report, so give them the one
    // precondition the predicate checks first: something to actually call.
    // The absence of it is covered in "fails closed" below.
    before(() => {
        Object.defineProperty(globalThis, "navigator", {
            value: { credentials: { get: async () => null, create: async () => null } },
            configurable: true,
            writable: true,
        });
    });

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

// offers.js calls navigator.credentials.create() whenever the predicate is
// true, and calls the predicate from Alpine's init(). So a probe that throws
// does not merely hide a button - it aborts the component and takes the QR
// rendering with it. Every one of these must be false, never a throw.
describe("isIssuanceAvailable fails closed", () => {
    /** @type {PropertyDescriptor | undefined} */
    let savedNavigator;

    before(() => {
        savedNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    });

    function setNavigator(value) {
        Object.defineProperty(globalThis, "navigator", {
            value,
            configurable: true,
            writable: true,
        });
    }

    afterEach(() => {
        if (savedNavigator) {
            Object.defineProperty(globalThis, "navigator", savedNavigator);
        } else {
            delete globalThis.navigator;
        }
        clearGlobals();
    });

    it("is false when navigator.credentials.create is missing", () => {
        setNavigator({ credentials: { get: async () => null } });
        // A shim can claim the protocol without providing the call it gates.
        globalThis.DigitalCredential = { userAgentAllowsProtocol: () => true };
        assert.equal(isIssuanceAvailable(), false);
    });

    it("is false when navigator.credentials is missing entirely", () => {
        setNavigator({});
        globalThis.DigitalWallets = { supportsProtocol: () => true };
        assert.equal(isIssuanceAvailable(), false);
    });

    it("is false, not a throw, when userAgentAllowsProtocol throws", () => {
        setNavigator({ credentials: { create: async () => null } });
        globalThis.DigitalCredential = {
            userAgentAllowsProtocol: () => {
                throw new Error("hostile shim");
            },
        };
        assert.equal(isIssuanceAvailable(), false);
    });

    it("is false, not a throw, when supportsProtocol throws", () => {
        setNavigator({ credentials: { create: async () => null } });
        globalThis.DigitalWallets = {
            supportsProtocol: () => {
                throw new Error("hostile registry");
            },
        };
        assert.equal(isIssuanceAvailable(), false);
    });

    it("ignores a truthy non-boolean from the native probe", () => {
        setNavigator({ credentials: { create: async () => null } });
        globalThis.DigitalCredential = { userAgentAllowsProtocol: () => "yes" };
        assert.equal(isIssuanceAvailable(), false);
    });

    it("is still true for genuine native support", () => {
        setNavigator({ credentials: { create: async () => null } });
        globalThis.DigitalCredential = {
            userAgentAllowsProtocol: (p) => p === "openid4vci-v1",
        };
        assert.equal(isIssuanceAvailable(), true);
    });
});

// offers.js is not exercised here (no Alpine, no DOM), so this is a source
// assertion rather than a behavioural one. It guards the invariant the whole
// block above exists for: the page must read the browser's own globals, which
// it can only do while nothing has installed the polyfill over them.
describe("offers.js polyfill invariant", () => {
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

    it("does not install the DC API polyfill", () => {
        assert.equal(
            /\binstallPolyfill\b/.test(source),
            false,
            "offers.js must not install the vendored polyfill: it shims " +
                "DigitalCredential.userAgentAllowsProtocol page-wide (and " +
                "fabricates the global outright when the browser has none), " +
                "so isIssuanceAvailable() would stop reporting native " +
                "support while still claiming to. Install it only together " +
                "with a combined bundle - sirosfoundation/dc-api#23.",
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
