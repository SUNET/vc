import Alpine from "alpinejs";
import * as v from "valibot";

/**
 * @typedef {Object} Credential
 * @property {string} vct
 * @property {string} name
 * @property {string} svg
 * @property {Record<string, { label: string; value: unknown; }>} claims
 */

/**
 * @typedef {v.InferOutput<typeof SvgTemplateResponseSchema>} SvgTemplateResponse
 */
const SvgTemplateResponseSchema = v.required(v.object({
    template: v.string(),
    svg_claims: v.record(v.string(), v.array(v.string())),
}));

/**
 * Recursive JSON-value schema for claim values. Claim values are always
 * delivered as JSON (string, number, boolean, null, or a nested object/array
 * of the same), so anything outside that set is rejected at parse time and
 * the consumer can rely on `typeof` checks at use sites.
 * @type {import('valibot').GenericSchema<unknown>}
 */
const ClaimValueSchema = v.lazy(() => v.union([
    v.string(),
    v.number(),
    v.boolean(),
    v.null(),
    v.array(ClaimValueSchema),
    v.record(v.string(), ClaimValueSchema),
]));

/**
 * @typedef {v.InferOutput<typeof UserDataSchema>} UserData
 */
const UserDataSchema = v.required(v.object({
    svg_template_claims: v.record(v.string(), v.object({
        label: v.string(),
        value: ClaimValueSchema,
    })),
    redirect_url: v.string(),
}));

/**
 * @param {string} key
 * @returns {string}
 */
function keyToLabel(key) {
    if (key.includes("_")) {
        let parts = key.split("_");

        parts[0] = parts[0].charAt(0).toUpperCase() + parts[0].slice(1);

        key = parts.join(" ");
    }

    return key;
}

/**
 * Escape a string for safe injection into HTML text content / attribute values.
 * @param {string} s
 * @returns {string}
 */
function escapeHtml(s) {
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
const SAFE_IMAGE_SUBTYPES = new Set(["png", "jpeg", "gif", "webp"]);

// Standard base64 alphabet (anchored elsewhere) — no URL-safe variants, no
// whitespace, no other characters.
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
function utf8ToBase64(s) {
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
function base64ToUtf8(b64) {
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
function detectBase64Image(s) {
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
 * arrays become a nested tree of indented key:value rows. Base64 image data
 * is rendered as an inline preview. Used via `x-html` in consent.html.
 * @param {unknown} value
 * @returns {string}
 */
function renderClaimValueHtml(value) {
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

/**
 * Due to bfcache some state will persist across
 * navigation events, so we 'manually' clear it.
 * @see https://developer.mozilla.org/en-US/docs/Glossary/bfcache
 */
window.addEventListener("pageshow", (event) => {
    if (event.persisted) {
        window.location.reload();
    }
});

const baseUrl = window.location.origin;

const ROUTES = {
    login: "#/",
    credentials: "#/credentials"
}

Alpine.data("app", () => ({
    /** @type {boolean} */
    loading: true,

    /** @type {string | null} */
    redirectUrl: null,

    /** @type {Credential[]} */
    credentials: [],

    /** @type {boolean} */
    loggedIn: false,

    /** @type {"saml" | "oidc" | "openid4vp" | null} */
    authMethod: null,

    /** @type {number | null} */
    openid4vpRedirectCountUp: null,

    /** @type {number} */
    openid4vpRedirectMaxCount: 7,

    /** @type {string | null} */
    error: null,

    init() {
        this.setAuthMethod();
        this.setRedirectUrl();

        this.hashState();

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });

        if (this.loggedIn) {
            this.handleIsLoggedIn();
        } else if (this.authMethod === "saml") {
            this.handleLoginSAML();
        } else if (this.authMethod === "oidc") {
            this.handleLoginOIDC();
        } else {
            this.loading = false;
        }

        this.$watch("loggedIn", (newVal) => {
            if (newVal) {
                this.handleIsLoggedIn();
            } else {
                this.handleIsNotLoggedIn();
            }
        });
    },

    setAuthMethod() {
        const authMethod = this.$el.dataset.authMethod || null;
        const validMethods = ["openid4vp", "saml", "oidc"];

        if (
            !authMethod ||
            authMethod !== "saml" &&
            authMethod !== "oidc" &&
            authMethod !== "openid4vp"
        ) {
            this.error = `Unknown auth method: '${authMethod}'`;
            return;
        }

        this.authMethod = authMethod;
    },

    setRedirectUrl() {
        const raw = this.$el.dataset.redirectUrl || null;
        if (raw) {
            this.redirectUrl = raw;
        }
    },

    hashState() {
        /** @param {string} hash */
        const updateLoginState = (hash) => {
            this.loggedIn = (hash === ROUTES.credentials);
        };

        updateLoginState(window.location.hash);

        addEventListener("hashchange", (event) => {
            this.loading = true;
            const { hash } = new URL(event.newURL);
            updateLoginState(hash);
            this.loading = false;
        });
    },

    handleLoginSAML() {
        const url = this.redirectUrl;
        if (!url) {
            this.error = "Missing SAML redirect URL";
            return;
        }
        this.redirect(url);
    },

    handleLoginOIDC() {
        const url = this.redirectUrl;
        if (!url) {
            this.error = "Missing OIDC redirect URL";
            return;
        }
        this.redirect(url);
    },

    /**
     * @param {boolean} immediate - Immediately proceed to 'redirect_uri'
     */
    handleLoginOpenID4VP(immediate = false) {
        const url = this.redirectUrl;
        if (!url) {
            this.error = "Missing OpenID4VP redirect URL";
            return;
        }

        if (immediate) {
            this.redirect(url);
            return;
        }

        this.openid4vpRedirectCountUp = 1;

        const increment = setInterval(() => {
            // We can stop the interval by setting
            // this.openid4vpRedirectCountUp to 'null'
            if (!this.openid4vpRedirectCountUp) {
                clearInterval(increment);
                return;
            }

            ++this.openid4vpRedirectCountUp;

            if (this.openid4vpRedirectCountUp >= this.openid4vpRedirectMaxCount) {
                clearInterval(increment);
                this.redirect(url);
                return;
            }
        }, 1000);
    },

    async handleIsNotLoggedIn() {
        this.credentials = [];
        this.$refs.title.innerText = "Authorization Consent";
    },

    async handleIsLoggedIn() {
        this.loading = true;

        const url = new URL("/user/lookup", baseUrl);

        const options = {
            method: "GET", 
            headers: {
                "Accept": "application/json", 
                "Content-Type": "application/json; charset=utf-8",
            }, 
        };

        try {
            const res = await this.fetchData(url.toString(), options);

            const data = v.parse(UserDataSchema, res);

            this.redirectUrl = data.redirect_url;

            let svg = null;
            try {
                svg = await this.createCredentialSvgImageUri(
                    data.svg_template_claims,
                );
            } catch (_) {
                // VCTM has no SVG template — display claims without card image
            }

            this.credentials.push({
                vct: "N/A",
                name: "PID",
                svg,
                claims: data.svg_template_claims,
            });

            const givenName = data.svg_template_claims.given_name?.value;
            if (typeof givenName === "string" && givenName.length > 0) {
                this.$refs.title.innerText = `Welcome, ${givenName}!`;
            }
        } catch (err) {
            if (err instanceof v.ValiError) {
                this.error = err.message;
            } else if (err instanceof Error) {
                this.error = `Error: ${err.message}`;
            } else {
                this.error = `Error: ${err}`;
            }
            window.location.hash = ROUTES.login;
        } finally {
            this.loading = false;
        }
    },

    /** @param {SubmitEvent} event */
    handleCredentialSelection(event) {
        const url = this.redirectUrl;
        if (!url) {
            this.error = "'redirect_url' is null";
            return;
        }
        this.redirect(url);
    },

    /**
     * @param {RequestInfo} url 
     * @param {RequestInit} options 
     * @returns {Promise<any>}
     */
    async fetchData(url, options) {
        const response = await fetch(url, options);
        if (!response.ok) {
            if (response.status === 401) {
                this.loggedIn = false;
                this.redirectUrl = null;
                this.credentials = [];

                throw new Error("Unauthorized/session expired");
            }
            throw new Error(`HTTP error! status: ${response.status}, url: ${url}`);
        }

        const data = await response.json();
        return data;
    },

    /**
     * @param {Record<string, { label: string; value: unknown; }>} claims
     * @returns {Promise<string>}
     */
    async createCredentialSvgImageUri(claims) {
        const url = new URL('/authorization/consent/svg-template', baseUrl);

        /** @type {SvgTemplateResponse} */
        const data = await this.fetchData(url.toString(), {});

        // Decode the template as UTF-8 — `atob` alone returns a Latin-1 byte
        // string, which would corrupt any non-ASCII characters in the SVG
        // when re-encoded with utf8ToBase64 below.
        let svg = base64ToUtf8(data.template);

        for (const [svg_id, claim] of Object.entries(claims)) {
            // SVG templates only substitute scalar text — skip nested
            // structures (those are rendered in the claims table as a tree).
            if (typeof claim.value !== "string") continue;
            // For image-bearing placeholders (e.g. <image href="{{picture}}"/>)
            // the raw base64 isn't a valid URL — convert to a data: URL so
            // browsers will actually render it inside the SVG.
            const raw = detectBase64Image(claim.value) ?? claim.value;
            // Escape for XML text/attribute contexts. Without this, a value
            // like O'Brien & Co. or "</text>..." would break SVG parsing or
            // alter its structure. Base64 data: URLs only use characters
            // [A-Za-z0-9+/=:;,/.] so escaping is a no-op for them.
            const value = escapeHtml(raw);
            svg = svg.replaceAll(`{{${svg_id}}}`, value);
        }

        return `data:image/svg+xml;base64,${utf8ToBase64(svg)}`;
    },

    /**
     * Renders a claim value as HTML. Primitive values become escaped text;
     * objects and arrays become nested <div> rows of indented key:value pairs.
     * Returned HTML is safe to set via x-html: all user-supplied strings are
     * passed through escapeHtml first.
     * @param {unknown} value
     * @returns {string}
     */
    renderClaimValue(value) {
        return renderClaimValueHtml(value);
    },

    /** @param {string} url */
    redirect(url) {
        this.loading = true;

        try {
            window.location.href = (new URL(url)).toString();
        } catch (err) {
            this.error = `Error when redirecting: ${err}`;
        }
    },
}));

Alpine.start();
