// Pure, DOM-free helpers used by consent.js. Kept in a separate module so
// they can be unit-tested under Node without pulling in Alpine, valibot, or
// the browser globals (window/document).

/**
 * @param {string} key
 * @returns {string}
 */
export function keyToLabel(key) {
    if (key.includes("_")) {
        let parts = key.split("_");

        parts[0] = parts[0].charAt(0).toUpperCase() + parts[0].slice(1);

        key = parts.join(" ");
    }

    return key;
}

/**
 * Escape a string for safe injection into HTML text content / attribute values.
 * The output is also valid XML, so it's used for SVG substitution as well.
 * @param {string} s
 * @returns {string}
 */
export function escapeHtml(s) {
    return s
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

// Raster image subtypes that are safe to inline as data: URLs in this UI.
// SVG (and other types that can carry script/external references) are
// intentionally excluded — they would execute in <img>/SVG <image href=…>
// contexts in some browsers.
export const SAFE_IMAGE_SUBTYPES = new Set(["png", "jpeg", "gif", "webp"]);

// Standard base64 alphabet — no URL-safe variants, no whitespace, no other
// characters.
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

// data:image/<subtype>;base64,<base64-payload>
const DATA_URL_RE = /^data:image\/([a-z0-9.+-]+);base64,([A-Za-z0-9+/]+={0,2})$/i;

/**
 * Base64-encode a string as UTF-8 bytes. `btoa` only accepts Latin-1
 * characters and throws on Unicode (e.g. "Penélope" in test data), which
 * would break the SVG card preview. Encode to UTF-8 first.
 * @param {string} s
 * @returns {string}
 */
export function utf8ToBase64(s) {
    const bytes = new TextEncoder().encode(s);
    let bin = "";
    // Build the Latin-1 string in chunks to avoid the argument-count limit
    // of String.fromCharCode for very long inputs (substituted card images
    // can be tens of KB).
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
        bin += String.fromCharCode.apply(null, /** @type {any} */(bytes.subarray(i, i + CHUNK)));
    }
    return btoa(bin);
}

/**
 * Decode a base64 string as UTF-8 text. The counterpart to `utf8ToBase64`:
 * `atob` alone produces a Latin-1 byte string where each char holds a raw
 * byte (0–255), which is the wrong shape for downstream string operations
 * if the source bytes are UTF-8 (non-ASCII chars become mojibake on re-encode).
 * @param {string} b64
 * @returns {string}
 */
export function base64ToUtf8(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8").decode(bytes);
}

/**
 * Detect base64-encoded image data and return a safe `data:` URL, or null if
 * the input isn't a recognized image. Showing a raw base64 blob in a consent
 * UI is useless — we render the picture instead.
 *
 * Only a small allowlist of raster MIME types is permitted, and the payload
 * must be base64-encoded. Anything else (SVG, plaintext data URLs, unknown
 * subtypes, base64 with stray characters) returns null.
 *
 * @param {string} s
 * @returns {string | null}
 */
export function detectBase64Image(s) {
    if (s.startsWith("data:")) {
        const m = DATA_URL_RE.exec(s);
        if (!m) return null;
        const subtype = m[1].toLowerCase();
        if (!SAFE_IMAGE_SUBTYPES.has(subtype)) return null;
        return `data:image/${subtype};base64,${m[2]}`;
    }
    // Bare base64 — sniff the decoded magic bytes via the base64 prefix and
    // require the full string to be valid standard base64.
    if (!BASE64_RE.test(s)) return null;
    // PNG: base64 of "\x89PNG\r\n\x1a\n..." starts with "iVBORw0KGgo"
    if (s.startsWith("iVBORw0KGgo")) return `data:image/png;base64,${s}`;
    // JPEG: base64 of "\xff\xd8\xff..." starts with "/9j/"
    if (s.startsWith("/9j/")) return `data:image/jpeg;base64,${s}`;
    // GIF: base64 of "GIF87a"/"GIF89a" starts with "R0lGO"
    if (s.startsWith("R0lGO")) return `data:image/gif;base64,${s}`;
    // WebP: base64 of "RIFF....WEBP" starts with "UklGR"
    if (s.startsWith("UklGR")) return `data:image/webp;base64,${s}`;
    return null;
}

/**
 * Render a claim value as HTML. Primitives become escaped text; objects and
 * arrays become nested <div> rows of indented key:value pairs. Base64 image
 * data is rendered as an inline preview. Used via `x-html` in consent.html.
 * @param {unknown} value
 * @returns {string}
 */
export function renderClaimValueHtml(value) {
    if (value === null || value === undefined) {
        return "";
    }

    if (Array.isArray(value)) {
        if (value.length === 0) return "";
        const items = value
            .map((v, i) => `<div class="flex gap-2"><span class="text-xs opacity-60 shrink-0 pt-0.5">${escapeHtml(String(i))}</span><div class="min-w-0 break-words">${renderClaimValueHtml(v)}</div></div>`)
            .join("");
        return `<div class="pl-3 space-y-0.5">${items}</div>`;
    }

    if (typeof value === "object") {
        const entries = Object.entries(/** @type {Record<string, unknown>} */(value));
        if (entries.length === 0) return "";
        const items = entries
            .map(([k, v]) => `<div class="flex gap-2"><span class="text-xs opacity-60 shrink-0 pt-0.5">${escapeHtml(keyToLabel(k))}:</span><div class="min-w-0 break-words">${renderClaimValueHtml(v)}</div></div>`)
            .join("");
        return `<div class="pl-3 space-y-0.5">${items}</div>`;
    }

    if (typeof value === "string") {
        const dataUrl = detectBase64Image(value);
        if (dataUrl) {
            return `<img src="${escapeHtml(dataUrl)}" alt="" class="max-h-32 rounded border border-black/10 dark:border-white/10" />`;
        }
        return escapeHtml(value);
    }

    return escapeHtml(String(value));
}
