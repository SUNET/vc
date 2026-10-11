// Handing a presentation request over to a wallet.
//
// Two shapes, and the difference between them is the whole reason this
// file exists:
//
//   - A CUSTOM SCHEME (openid4vp:, mdoc-openid4vp:, a vendor's own) hands
//     off to an installed app. Chrome on Android only lets a page do that
//     while it still holds the transient user activation from the click,
//     and one `await` is enough to lose it - after which the navigation is
//     a silent no-op: no exception, nothing in the console, and no
//     ACTION_VIEW intent in logcat at all. So nothing may be awaited
//     before it. The page is NOT replaced, so it stays live on its SSE
//     stream either way.
//
//   - An http(s) WEB WALLET is an ordinary navigation. It needs no
//     activation, and it REPLACES this page. The preference POST is
//     therefore confirmed first, so that a failure can still be recovered
//     by sending the wallet to a second tab and leaving this one alive to
//     finish the flow.
//
// The preference matters because the verifier only returns redirect_uri
// from direct_post when the session is marked same-device; without it the
// wallet has nowhere to send the user back to.

/**
 * Whether handing off to this URL replaces the current page.
 *
 * A URL that does not parse is treated as a custom scheme: navigating
 * synchronously is the safe answer either way, and guessing "web wallet"
 * would lose the activation this module exists to preserve.
 *
 * @param {string} url
 * @returns {boolean}
 */
export function walletHandoffReplacesPage(url) {
    try {
        const { protocol } = new URL(url);
        return protocol === "http:" || protocol === "https:";
    } catch {
        return false;
    }
}

/**
 * The browser seams handOffToWallet needs, so a test can observe the
 * ORDER of what it does rather than only its result.
 *
 * @typedef {object} HandoffEnv
 * @property {(url: string, data: Blob) => boolean} [sendBeacon] navigator.sendBeacon, when the browser has it.
 * @property {(url: string, init: RequestInit) => Promise<Response>} fetch
 * @property {(url: string) => void} navigate Replace the current page.
 * @property {(url: string) => any} openTab Open a tab; null when blocked.
 */

/**
 * Hand the request to the wallet at url, recording the same-device
 * preference on the way.
 *
 * @param {string} url
 * @param {string} endpoint Absolute URL of /verification/session-preference.
 * @param {object} preference JSON body for that endpoint.
 * @param {HandoffEnv} env
 */
export async function handOffToWallet(url, endpoint, preference, env) {
    const body = JSON.stringify(preference);

    if (!walletHandoffReplacesPage(url)) {
        // Deliberately not awaited, and the navigation is deliberately the
        // next statement: both are the fix for the silent no-op above.
        postPreferenceInBackground(endpoint, body, env);
        env.navigate(url);
        return;
    }

    // Opened inside the click so the browser still counts a live user
    // activation when the fallback runs after the awaited fetch.
    // No `noopener`: that feature makes window.open return null and then
    // we would not be able to close or navigate the placeholder. Severed
    // manually below (opener = null) before any navigation.
    const fallbackWindow = env.openTab("");
    try {
        const res = await env.fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body,
        });
        if (!res.ok) {
            throw new Error(`session-preference returned ${res.status}`);
        }
        if (fallbackWindow && !fallbackWindow.closed) {
            fallbackWindow.close();
        }
        env.navigate(url);
    } catch (err) {
        console.error("Failed to mark same-device flow, opening wallet in a new tab so this page can still redirect", err);
        if (fallbackWindow && !fallbackWindow.closed) {
            try { fallbackWindow.opener = null; } catch { /* cross-origin after nav */ }
            fallbackWindow.location.href = url;
        } else {
            // Popup blocker denied the pre-opened tab; last-resort try
            // (likely blocked too, but worth attempting).
            env.openTab(url);
        }
    }
}

/**
 * Send the preference so it survives this task without being waited on.
 *
 * sendBeacon first: it is specified to be queued and delivered by the
 * browser independently of the page, which is exactly the guarantee
 * wanted when the next statement hands control to another app. keepalive
 * gives a fetch the same property where sendBeacon is missing or its
 * queue is full.
 *
 * A failure here is not fatal. The verifier then treats the session as
 * cross-device and withholds redirect_uri, so the wallet does not send
 * the user back - but this page is still open on its SSE stream and still
 * shows the result, which is the flow the preference was an optimisation
 * over.
 *
 * @param {string} endpoint
 * @param {string} body
 * @param {HandoffEnv} env
 */
function postPreferenceInBackground(endpoint, body, env) {
    try {
        if (env.sendBeacon?.(endpoint, new Blob([body], { type: "application/json" }))) {
            return;
        }
    } catch (err) {
        console.error("sendBeacon for the same-device flag failed", err);
    }

    env.fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        keepalive: true,
    }).catch((err) => {
        console.error("Failed to mark same-device flow; the wallet will not be sent back here", err);
    });
}

/**
 * The real browser's seams.
 *
 * @param {any} [scope]
 * @returns {HandoffEnv}
 */
export function browserHandoffEnv(scope = globalThis) {
    return {
        sendBeacon: scope.navigator?.sendBeacon
            ? (url, data) => scope.navigator.sendBeacon(url, data)
            : undefined,
        fetch: (url, init) => scope.fetch(url, init),
        navigate: (url) => { scope.location.href = url; },
        openTab: (url) => scope.open(url, "_blank"),
    };
}
