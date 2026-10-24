// Unit tests for reading a refusal out of an /ui/notify message.
//
// The bug these exist for was an omission, not a wrong answer: the
// listener filtered every message on `redirect_uri` and returned early
// otherwise, so a refusal - which has no redirect_uri - was indistinguish-
// able from a keep-alive. The page went on showing the QR for a request
// the user had already said no to, until the presentation deadline.
//
// Runs under Node's built-in test runner (`node --test`).

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
    declineFromNotifyMessage,
    declineDescriptionFromNotifyMessage,
} from "../notify-decline.js";

describe("declineFromNotifyMessage", () => {
    it("reads the error code the verifier forwards for a refusal", () => {
        assert.equal(
            declineFromNotifyMessage(JSON.stringify({ error: "access_denied" })),
            "access_denied",
        );
    });

    it("keeps a code other than access_denied", () => {
        // Section 8.5 names access_denied for a refused consent, but a
        // wallet may refuse for its own reasons and the page should say
        // which.
        assert.equal(
            declineFromNotifyMessage(JSON.stringify({ error: "invalid_request" })),
            "invalid_request",
        );
    });

    it("treats a description with no code as a refusal", () => {
        // Still terminal. Reporting nothing here would hang the page on
        // a message that plainly says the request is over.
        assert.equal(
            declineFromNotifyMessage(JSON.stringify({ error_description: "user said no" })),
            "access_denied",
        );
    });

    it("does not read a completion as a refusal", () => {
        // The field order matters: redirect_uri settles the message
        // before "error" is looked for anywhere in it.
        const completion = JSON.stringify({
            redirect_uri: "https://rp.example/cb?response_code=abc&error_hint=none",
        });
        assert.equal(declineFromNotifyMessage(completion), "");
    });

    it("ignores keep-alives and anything that is not a message", () => {
        for (const noise of ["", " ", "ping", "{}", null, undefined, 42, {}]) {
            assert.equal(declineFromNotifyMessage(noise), "",
                `expected no decline from ${JSON.stringify(noise)}`);
        }
    });

    it("falls back to the textual form when the payload is not JSON", () => {
        assert.equal(declineFromNotifyMessage("error=access_denied"), "access_denied");
        assert.equal(declineFromNotifyMessage("error: access_denied"), "access_denied");
    });

    it("does not report an empty code as a refusal", () => {
        // "" is falsy at the call site, so reporting it would close the
        // stream and then show a decline screen naming nothing.
        assert.equal(declineFromNotifyMessage(JSON.stringify({ error: "" })), "");
    });
});

describe("declineDescriptionFromNotifyMessage", () => {
    it("returns the wallet's own text when there is one", () => {
        assert.equal(
            declineDescriptionFromNotifyMessage(
                JSON.stringify({ error: "access_denied", error_description: "consent declined" }),
            ),
            "consent declined",
        );
    });

    it("returns nothing when the refusal carried no description", () => {
        assert.equal(declineDescriptionFromNotifyMessage(JSON.stringify({ error: "access_denied" })), "");
        assert.equal(declineDescriptionFromNotifyMessage("error=access_denied"), "");
    });
});
