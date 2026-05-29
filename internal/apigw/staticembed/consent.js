import Alpine from "alpinejs";
import * as v from "valibot";

import {
    base64ToUtf8,
    escapeHtml,
    renderClaimValueHtml,
    utf8ToBase64,
    valueForSvgPlaceholder,
} from "./consent-helpers.js";

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
            // valueForSvgPlaceholder decides what (if anything) is safe to
            // substitute for this placeholder. Image-bearing slots only
            // accept validated data: URLs — arbitrary strings are coerced
            // to "" so the consent page can't be made to fetch external
            // URLs at render time. Text slots pass scalar strings through.
            const resolved = valueForSvgPlaceholder(svg_id, claim.value);
            if (resolved === null) continue;
            // Escape for XML text/attribute contexts. Without this, a value
            // like O'Brien & Co. or "</text>..." would break SVG parsing or
            // alter its structure. Base64 data: URLs only use characters
            // [A-Za-z0-9+/=:;,/.] so escaping is a no-op for them.
            svg = svg.replaceAll(`{{${svg_id}}}`, escapeHtml(resolved));
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
