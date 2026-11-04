// The payment page's wallet link.
//
// A module rather than inline script so it can be tested the way
// wallet-handoff.js is: the thing worth testing here is not that a link
// navigates, it is WHICH clicks record the same-device preference and
// that nothing is awaited before a custom-scheme launch.

import { browserHandoffEnv, handOffToWallet } from "./wallet-handoff.js";

/**
 * Arm a wallet link for one session.
 *
 * The preference matters because /verification/direct_post only returns
 * redirect_uri for a session marked same-device; without it the wallet
 * has nowhere to send the user back to and the operator has to find the
 * page again by hand.
 *
 * It cannot simply be POSTed and awaited before the navigation: Chrome
 * on Android only lets a page launch a custom scheme while it still
 * holds the click's transient user activation, and one await loses it -
 * silently, with no exception and no intent. handOffToWallet is where
 * that ordering is already worked out.
 *
 * Only a plain left click hands off. A modified click (new tab, new
 * window, download) must stay an ordinary link: the preference is about
 * THIS browser following the redirect back, and a click that opens
 * somewhere else is not that. Scanning the QR code is likewise a
 * cross-device flow, which is why nothing arms it.
 *
 * @param {{href: string, onclick: ((ev: any) => void) | null}} link
 * @param {string} sessionID
 * @param {string} origin Page origin, for resolving the endpoint.
 * @param {import("./wallet-handoff.js").HandoffEnv} [env]
 */
export function armWalletLink(link, sessionID, origin, env = browserHandoffEnv()) {
    link.onclick = (ev) => {
        if (ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) {
            return;
        }
        ev.preventDefault();
        // Not awaited - a click handler cannot be - but the rejection is
        // caught, so a failure here is a line in the console rather than
        // an unhandled rejection the operator never sees.
        handOffToWallet(
            link.href,
            new URL("/verification/session-preference", origin).toString(),
            { session_id: sessionID, wallet_follows_redirect: true },
            env,
        ).catch((err) => {
            console.error("Failed to hand the payment request to the wallet", err);
        });
    };
}
