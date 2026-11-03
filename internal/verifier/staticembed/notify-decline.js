/**
 * Reading a refusal out of an /ui/notify message.
 *
 * The notify stream carries two kinds of terminal news for a waiting
 * page: a completion, which carries a redirect_uri, and a refusal, which
 * does not. The listener used to filter on `redirect_uri` alone, so a
 * refusal was dropped and the page waited for a wallet that had already
 * answered. This is the half that decides, kept separate so it can be
 * tested without an EventSource.
 */

/** A refusal with no error code of its own. Section 8.5 of OpenID4VP
 * 1.0 names access_denied for a user who did not consent, and that is
 * what a wallet with nothing more specific to say sends. */
const DEFAULT_DECLINE_ERROR = "access_denied";

/**
 * The error code of a refusal carried by one SSE message, or "" when the
 * message is not a refusal.
 *
 * A completion is never a refusal, even if some field of it happens to
 * contain the substring "error": the presence of redirect_uri settles
 * it, and that check comes first.
 *
 * The payload SHOULD be JSON. It is parsed leniently because this is the
 * last hop of a flow the user is watching: a message that says "error"
 * in a shape we did not predict is still better treated as the refusal
 * it plainly is than left to time out.
 *
 * @param {unknown} data One SSE message's data field.
 * @returns {string} The error code, or "" if this message is not a refusal.
 */
export function declineFromNotifyMessage(data) {
    if (!data || typeof data !== "string") return "";
    if (data.includes("redirect_uri")) return "";
    if (!data.includes("error")) return "";

    try {
        const parsed = JSON.parse(data);
        if (parsed && typeof parsed === "object") {
            if (typeof parsed.error === "string" && parsed.error) return parsed.error;
            // A well-formed object that named no code is still a
            // refusal - "error_description only" is a shape wallets do
            // send - and treating it as noise would hang the page.
            if (typeof parsed.error_description === "string" && parsed.error_description) {
                return DEFAULT_DECLINE_ERROR;
            }
            return "";
        }
    } catch {
        // Not JSON. Fall through to the textual form below.
    }

    const match = data.match(/error[=:]\s*["']?([^"'\s,}]+)/);
    if (match && match[1]) return match[1];
    return "";
}

/**
 * The description a refusal carried, or "" when it carried none. Shown
 * as supporting text and never acted on: it is the wallet's own prose.
 *
 * @param {unknown} data One SSE message's data field.
 * @returns {string}
 */
export function declineDescriptionFromNotifyMessage(data) {
    if (!data || typeof data !== "string") return "";
    try {
        const parsed = JSON.parse(data);
        if (parsed && typeof parsed === "object" && typeof parsed.error_description === "string") {
            return parsed.error_description;
        }
    } catch {
        return "";
    }
    return "";
}
