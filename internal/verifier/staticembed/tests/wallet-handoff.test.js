// Unit tests for the wallet handoff. Runs under Node's built-in test
// runner (`node --test`) - no extra dependencies.
//
// These are ORDER tests, not result tests. The bug they exist for was a
// correct-looking handler that did the right things in the wrong order:
// one `await` before the navigation, which on Android Chrome costs the
// click's transient user activation and turns the launch into a silent
// no-op. Asserting only that the page navigated eventually would pass
// with the bug present.

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { browserHandoffEnv, handOffToWallet, walletHandoffReplacesPage } from "../wallet-handoff.js";

const ENDPOINT = "https://verifier.example.com/verification/session-preference";
const PREFERENCE = { session_id: "s-1", wallet_follows_redirect: true };

/**
 * A recording env whose fetch never settles, so anything that happens
 * after awaiting it has provably not happened yet.
 */
function env(overrides = {}) {
    const calls = [];
    const base = {
        calls,
        sendBeacon: (url, data) => { calls.push(["sendBeacon", url, data]); return true; },
        fetch: (url, init) => { calls.push(["fetch", url, init]); return new Promise(() => {}); },
        navigate: (url) => { calls.push(["navigate", url]); },
        openPlaceholder: () => { calls.push(["openPlaceholder"]); return { closed: false, close() { this.closed = true; }, location: {} }; },
        openExternal: (url) => { calls.push(["openExternal", url]); },
    };
    return Object.assign(base, overrides);
}

const names = (e) => e.calls.map((c) => c[0]);

describe("walletHandoffReplacesPage", () => {
    it("is true for a web wallet, which navigates away from this page", () => {
        assert.equal(walletHandoffReplacesPage("https://wallet.example.com/request?x=1"), true);
        assert.equal(walletHandoffReplacesPage("http://localhost:8080/request"), true);
    });

    it("is false for the custom schemes that hand off to an app", () => {
        assert.equal(walletHandoffReplacesPage("openid4vp://?request_uri=x"), false);
        assert.equal(walletHandoffReplacesPage("mdoc-openid4vp://?request_uri=x"), false);
        assert.equal(walletHandoffReplacesPage("eudi-openid4vp://x"), false);
    });

    it("treats an unparseable URL as a custom scheme", () => {
        // Navigating synchronously is safe either way; guessing "web
        // wallet" would spend the activation this module protects.
        assert.equal(walletHandoffReplacesPage("not a url"), false);
    });
});

describe("handOffToWallet with a custom scheme", () => {
    it("navigates in the same task as the click, before anything is awaited", () => {
        const e = env();
        // Deliberately not awaited: everything asserted here has to have
        // happened before this function yielded, which is what "still
        // holds the user activation" means.
        void handOffToWallet("openid4vp://?request_uri=x", ENDPOINT, PREFERENCE, e);

        assert.deepEqual(names(e), ["sendBeacon", "navigate"]);
        assert.equal(e.calls[1][1], "openid4vp://?request_uri=x");
    });

    it("opens no placeholder tab", () => {
        // The page is not replaced by an app launch, so it survives to
        // receive the result on its SSE stream - there is nothing for a
        // second tab to rescue.
        const e = env();
        void handOffToWallet("openid4vp://?request_uri=x", ENDPOINT, PREFERENCE, e);
        assert.equal(names(e).includes("openPlaceholder"), false);
    });

    it("still navigates when the preference cannot be sent at all", () => {
        const e = env({
            sendBeacon: () => { throw new Error("queue full"); },
            fetch: (url, init) => { e.calls.push(["fetch", url, init]); return Promise.reject(new Error("offline")); },
        });
        void handOffToWallet("openid4vp://?request_uri=x", ENDPOINT, PREFERENCE, e);

        assert.deepEqual(names(e), ["fetch", "navigate"]);
        assert.equal(e.calls[0][2].keepalive, true,
            "a fetch that has to outlive the handoff must say so");
    });

    it("falls back to a keepalive fetch when sendBeacon declines", () => {
        const e = env({ sendBeacon: () => false });
        void handOffToWallet("openid4vp://?request_uri=x", ENDPOINT, PREFERENCE, e);

        assert.deepEqual(names(e), ["fetch", "navigate"]);
        assert.equal(e.calls[0][2].keepalive, true);
    });
});

describe("handOffToWallet with a web wallet", () => {
    it("confirms the preference before replacing this page", async () => {
        const e = env();
        void handOffToWallet("https://wallet.example.com/request", ENDPOINT, PREFERENCE, e);

        // The fetch is in flight and the page is still here: an http(s)
        // navigation needs no activation, so there is nothing to lose by
        // waiting, and plenty to lose by not - a failed POST means the
        // wallet gets no redirect_uri back.
        assert.deepEqual(names(e), ["openPlaceholder", "fetch"]);

        await Promise.resolve();
        assert.deepEqual(names(e), ["openPlaceholder", "fetch"]);
    });

    it("sends the wallet to the pre-opened tab when the preference fails", async () => {
        const opened = { closed: false, close() { this.closed = true; }, location: {} };
        const e = env({
            openPlaceholder: () => { e.calls.push(["openPlaceholder"]); return opened; },
            fetch: (url, init) => { e.calls.push(["fetch", url, init]); return Promise.resolve({ ok: false, status: 500 }); },
        });
        await handOffToWallet("https://wallet.example.com/request", ENDPOINT, PREFERENCE, e);

        assert.equal(opened.location.href, "https://wallet.example.com/request",
            "this page has to stay alive to finish a flow the verifier thinks is cross-device");
        assert.equal(names(e).includes("navigate"), false);
    });

    it("navigates this page once the preference is recorded", async () => {
        const opened = { closed: false, close() { this.closed = true; }, location: {} };
        const e = env({
            openPlaceholder: () => { e.calls.push(["openPlaceholder"]); return opened; },
            fetch: (url, init) => { e.calls.push(["fetch", url, init]); return Promise.resolve({ ok: true, status: 200 }); },
        });
        await handOffToWallet("https://wallet.example.com/request", ENDPOINT, PREFERENCE, e);

        assert.deepEqual(names(e), ["openPlaceholder", "fetch", "navigate"]);
        assert.equal(opened.closed, true, "the placeholder tab was left behind");
    });
});

describe("handOffToWallet when the placeholder tab is blocked", () => {
    it("opens the web wallet severed from this tab", async () => {
        // A web wallet that keeps window.opener can navigate the tab
        // holding the presentation - reverse tabnabbing. The placeholder
        // keeps an opener because this page has to close and steer it;
        // a direct open of the wallet URL has no such need.
        const e = env({
            openPlaceholder: () => { e.calls.push(["openPlaceholder"]); return null; },
            fetch: (url, init) => { e.calls.push(["fetch", url, init]); return Promise.resolve({ ok: false, status: 500 }); },
        });
        await handOffToWallet("https://wallet.example.com/request", ENDPOINT, PREFERENCE, e);

        assert.deepEqual(names(e), ["openPlaceholder", "fetch", "openExternal"]);
        assert.equal(e.calls[2][1], "https://wallet.example.com/request");
    });
});

describe("browserHandoffEnv", () => {
    /** A scope that records what window.open was actually asked for. */
    function scope() {
        const opens = [];
        return {
            opens,
            open: (...args) => { opens.push(args); return { closed: false }; },
            location: {},
            navigator: {},
            fetch: () => Promise.resolve({ ok: true }),
        };
    }

    it("severs the opener when it opens a wallet URL directly", () => {
        // Asserted on the window.open ARGUMENTS, not on the seam being
        // called: the feature string is the whole fix, and a test that
        // only checks "openExternal ran" passes with noopener dropped.
        const s = scope();
        browserHandoffEnv(s).openExternal("https://wallet.example.com/request");
        assert.deepEqual(s.opens, [["https://wallet.example.com/request", "_blank", "noopener"]]);
    });

    it("keeps the opener on the blank placeholder", () => {
        // noopener makes window.open return null, and then this page can
        // neither close the placeholder nor steer it at the wallet.
        const s = scope();
        const handle = browserHandoffEnv(s).openPlaceholder();
        assert.deepEqual(s.opens, [["", "_blank"]]);
        assert.notEqual(handle, null);
    });

    it("leaves sendBeacon undefined where the browser has none", () => {
        const s = scope();
        assert.equal(browserHandoffEnv(s).sendBeacon, undefined);
    });
});
