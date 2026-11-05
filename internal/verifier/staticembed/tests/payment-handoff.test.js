// Unit tests for the payment page's wallet link.
//
// The defect these exist for: the link was an ordinary anchor, so no
// session was ever marked same-device and /verification/direct_post
// returned no redirect_uri - the wallet had nowhere to send the user
// back to, and the operator had to find the polling page by hand.
//
// Like wallet-handoff.test.js these are ORDER tests as much as result
// tests: the preference must not be awaited before a custom-scheme
// launch, or Android Chrome drops the click's transient activation and
// the launch becomes a silent no-op.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { armWalletLink } from "../payment-handoff.js";

const ORIGIN = "https://verifier.example.com";
const ENDPOINT = `${ORIGIN}/verification/session-preference`;

function env() {
    const calls = [];
    return {
        calls,
        sendBeacon: (url, data) => { calls.push(["sendBeacon", url, data]); return true; },
        // Never settles, so anything after an await provably has not run.
        fetch: (url, init) => { calls.push(["fetch", url, init]); return new Promise(() => {}); },
        navigate: (url) => { calls.push(["navigate", url]); },
        openPlaceholder: () => { calls.push(["openPlaceholder"]); return { closed: false, close() { this.closed = true; }, location: {} }; },
        openExternal: (url) => { calls.push(["openExternal", url]); },
    };
}

function click(overrides = {}) {
    let defaultPrevented = false;
    return {
        button: 0, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false,
        preventDefault() { defaultPrevented = true; },
        get defaultPrevented() { return defaultPrevented; },
        ...overrides,
    };
}

describe("armWalletLink", () => {
    it("records the session as same-device and launches the wallet", async () => {
        const link = { href: "openid4vp://?request_uri=x", onclick: null };
        const e = env();
        armWalletLink(link, "s-1", ORIGIN, e);

        const ev = click();
        link.onclick(ev);

        assert.equal(ev.defaultPrevented, true, "the anchor must not navigate on its own");
        const beacon = e.calls.find((c) => c[0] === "sendBeacon");
        assert.ok(beacon, "the preference must be sent, or direct_post returns no redirect_uri");
        assert.equal(beacon[1], ENDPOINT);
        // sendBeacon takes a Blob, so the body is read back as text.
        assert.deepEqual(JSON.parse(await beacon[2].text()), {
            session_id: "s-1",
            wallet_follows_redirect: true,
        }, "the preference names THIS session; a cookie fallback would claim another tab's");
        assert.deepEqual(e.calls.map((c) => c[0]), ["sendBeacon", "navigate"],
            "nothing may be awaited before a custom-scheme launch");
    });

    it("leaves a modified click as an ordinary link", () => {
        for (const key of ["metaKey", "ctrlKey", "shiftKey", "altKey"]) {
            const link = { href: "openid4vp://?request_uri=x", onclick: null };
            const e = env();
            armWalletLink(link, "s-1", ORIGIN, e);

            const ev = click({ [key]: true });
            link.onclick(ev);

            assert.equal(ev.defaultPrevented, false, `${key} opens elsewhere; that is not this browser following the redirect`);
            assert.deepEqual(e.calls, [], `${key} must not mark the session same-device`);
        }
    });

    it("leaves a middle click alone", () => {
        const link = { href: "openid4vp://?request_uri=x", onclick: null };
        const e = env();
        armWalletLink(link, "s-1", ORIGIN, e);

        const ev = click({ button: 1 });
        link.onclick(ev);

        assert.equal(ev.defaultPrevented, false);
        assert.deepEqual(e.calls, []);
    });

    it("uses the href at CLICK time, not the one armed with", () => {
        // The page arms the link and then a later reply can replace the
        // href; sending the stale one would hand the wallet another
        // session's request.
        const link = { href: "openid4vp://?request_uri=first", onclick: null };
        const e = env();
        armWalletLink(link, "s-1", ORIGIN, e);
        link.href = "openid4vp://?request_uri=second";

        link.onclick(click());

        assert.deepEqual(e.calls.filter((c) => c[0] === "navigate"), [["navigate", "openid4vp://?request_uri=second"]]);
    });

    it("confirms the preference first for a web wallet, which replaces this page", () => {
        const link = { href: "https://wallet.example.com/request?x=1", onclick: null };
        const e = env();
        armWalletLink(link, "s-1", ORIGIN, e);

        link.onclick(click());

        // The fetch never settles, so the navigation has provably not
        // happened: a web wallet replaces this page, so a failed
        // preference must still be recoverable.
        assert.deepEqual(e.calls.map((c) => c[0]), ["openPlaceholder", "fetch"]);
    });
});
