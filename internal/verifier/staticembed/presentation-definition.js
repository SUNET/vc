import Alpine from "alpinejs";
import * as v from "valibot";
import {
    configure as configureDCAPI,
    isNativeDCAPIAvailable,
    getBestSupportedProtocol,
    requestCredentialFromAuthorizationRequestURI,
} from "./dc-api-polyfill.js";

/** @typedef {v.InferOutput<typeof credentialAttributesSchema>} CredentialAttributes */
const credentialAttributesSchema = v.object({
    format: v.string(),
    vct: v.string(),
    attributes: v.record(
        v.string(),
        v.record(
            v.string(),
            v.array(v.nullable(v.string())),
        ),
    ),
});

/**
 * @typedef {{ label: string; path: (string|null)[]; children: ClaimNode[] }} ClaimNode
 */

/**
 * Build a tree of claim nodes from a flat claims map.
 * Groups nested claims (path.length > 1) under their parent object.
 * @param {Record<string, (string|null)[]>} claims - label → path mapping
 * @returns {ClaimNode[]}
 */
function buildClaimTree(claims) {
    /** @type {ClaimNode[]} */
    const roots = [];
    /** @type {Map<string, ClaimNode>} */
    const parentMap = new Map();

    // First pass: identify parent nodes (path.length === 1 that have children)
    const entries = Object.entries(claims);
    const childEntries = entries.filter(([, path]) => path.length > 1);
    const parentKeys = new Set(childEntries.map(([, path]) => path[0]).filter(k => k !== null));

    for (const [label, path] of entries) {
        if (path.length === 1 && path[0] !== null && parentKeys.has(path[0])) {
            // This is a parent node (object or array) that has children.
            // If a synthetic parent was already created (child iterated first),
            // upgrade it in place rather than creating a duplicate.
            const existing = parentMap.get(path[0]);
            if (existing) {
                existing.label = label;
                existing.path = path;
            } else {
                const node = { label, path, children: [] };
                parentMap.set(path[0], node);
                roots.push(node);
            }
        } else if (path.length > 1 && path[0] !== null) {
            // This is a child — attach to parent
            const parentKey = path[0];
            let parent = parentMap.get(parentKey);
            if (!parent) {
                // Parent has no display entry; create a synthetic one
                parent = { label: parentKey, path: [parentKey], children: [] };
                parentMap.set(parentKey, parent);
                roots.push(parent);
            }
            parent.children.push({ label, path, children: [] });
        } else {
            // Simple top-level claim
            roots.push({ label, path, children: [] });
        }
    }

    return roots;
}

/** @typedef {v.InferOutput<typeof credentialsList>} CredentialsList */
const credentialsList = v.record(
    v.string(),
    credentialAttributesSchema,
);

/** @typedef {v.InferOutput<typeof metadataResponseSchema>} MetadataResponse */
const metadataResponseSchema = v.object({
    credentials: credentialsList,
    // v.optional() only substitutes its default for an ABSENT key, not an
    // explicit null - Go's zero-value nil map marshals to JSON null (see
    // UIMetadata's SupportedWallets fix), so this needs v.nullish() to
    // actually tolerate that, not v.optional().
    supported_wallets: v.nullish(v.record(v.string(), v.string()), {}),
    dc_api_enabled: v.optional(v.boolean(), false),
    presets: v.optional(v.record(v.string(), v.object({
        label: v.string(),
        credentials: v.array(v.object({
            id: v.string(),
            format: v.string(),
            meta: v.object({
                vct_values: v.array(v.string()),
            }),
            claims: v.optional(v.array(v.object({
                path: v.array(v.nullable(v.string())),
            }))),
            validations: v.optional(v.array(v.object({
                rule: v.string(),
                path: v.array(v.string()),
                value: v.any(),
            }))),
        })),
    }))),
})

/** @typedef {v.InferOutput<typeof dcqlQueryCredentialSchema>} DCQLQueryCredential */
const dcqlQueryCredentialSchema = v.object({
    id: v.string(),
    format: v.optional(v.string(), "dc+sd-jwt"),
    // vct_values (dc+sd-jwt/jwt_vc_json) and doctype_value (mso_mdoc) are
    // both optional here, not either/or required - which meta property
    // applies depends on the credential's format (OpenID4VP 1.0 6.4.1).
    meta: v.intersect([
        v.object({
            vct_values: v.optional(v.array(v.string())),
            doctype_value: v.optional(v.string()),
        }),
        v.record(v.string(), v.union([v.string(), v.array(v.string())])),
    ]),
    claims: v.optional(v.array(v.object({
        path: v.array(v.nullable(v.string())),
    }))),
});

const credentialSetQuerySchema = v.object({
    options: v.array(v.array(v.string())),
    required: v.optional(v.boolean()),
    purpose: v.optional(v.string()),
});

/** @typedef {v.InferOutput<typeof dcqlQuerySchema>} DCQLQuery */
const dcqlQuerySchema = v.object({
    credentials: v.array(dcqlQueryCredentialSchema),
    credential_sets: v.optional(v.array(credentialSetQuerySchema)),
});

/** @typedef {v.InferOutput<typeof presentationDefinitionSchema>} PresentationDefinition */
const presentationDefinitionSchema = v.object({
    qr_code: v.string(),
    authorization_request: v.string(),
});

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

const baseUrl = new URL(window.location.origin);

/**
 * Listen for SSE notifications from the server.
 * When a response_code is received, redirect to the callback URL.
 */
function setupNotifyListener() {
    console.log("Setting up SSE notify listener");
    const eventSource = new EventSource(new URL("/ui/notify", baseUrl).toString());

    eventSource.onopen = () => {
        console.log("SSE connection opened");
    };

    eventSource.onmessage = (event) => {
        const data = event.data;
        console.log("SSE message received:", data);
        
        // Check if the message contains a redirect_uri
        if (data && typeof data === "string" && data.includes("redirect_uri")) {
            try {
                const parsed = JSON.parse(data);
                if (parsed.redirect_uri) {
                    console.log("Redirecting to:", parsed.redirect_uri);
                    eventSource.close();
                    window.location.href = parsed.redirect_uri;
                }
            } catch {
                // Try to extract redirect_uri directly if not valid JSON
                const match = data.match(/redirect_uri[=:]["']?([^"'\s]+)/);
                if (match && match[1]) {
                    console.log("Redirecting to (regex):", match[1]);
                    eventSource.close();
                    window.location.href = match[1];
                }
            }
        }
    };

    eventSource.onerror = (error) => {
        console.error("SSE connection error:", error);
    };

    return eventSource;
}

Alpine.data("app", () => ({
    /** @type {boolean} */
    loading: true,

    /** @type {string | null} */
    error: null,

    /** @type {CredentialsList | null} */
    credentialsList: null,

    /** @type {Record<string, string> | null} */
    walletInstances: null,

    /** @type {boolean} Whether the server has opted in to native DC API attempts. */
    dcApiEnabled: false,

     /** @type {{ id: string; format: string; vct: string; claims: Record<string, (string|null)[]>; claimTree: ClaimNode[]; } | null} */
    credentialAttributes: null,

    /** 
     * @type {Record<string, object>} 
     */
    predefinedPresentationDefinitions: {},

    /** @type {DCQLQuery | null} */
    dcqlQuery: null,

    /** @type {Record<string, Array<{rule: string, path: string[], value: any}>> | null} */
    validations: null,

    /** @type {PresentationDefinition | null} */
    presentationDefinition: null,

    /** @type {Record<string, string> | null} */
    redirectUris: null,

    /** @type {EventSource | null} */
    notifyEventSource: null,

    /** @type {boolean} Set once a native DC API presentation has been submitted and accepted. */
    dcApiVerified: false,

    async init() {
        await this.lookupCredentialsList();

        this.loading = false;

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });

    },

    async lookupCredentialsList() {
        const res = await this.fetchData(new URL("/ui/metadata", baseUrl), {});

        const data = v.parse(metadataResponseSchema, res);

        this.credentialsList = data.credentials;
        this.walletInstances = data.supported_wallets;
        this.dcApiEnabled = data.dc_api_enabled;

        // Load presets from backend config
        if (data.presets) {
            this.predefinedPresentationDefinitions = data.presets;
        }
    },

    /** @param {string} id */
    async handleSelectPredefinedPresentationDefinition(id) {
        this.error = null;
        this.loading = true;
        
        const preset = /** @type {any} */ (this.predefinedPresentationDefinitions[id]);
        if (!preset) {
            this.error = `Unknown preset "${id}"`;
            this.loading = false;
            return;
        }

        // Extract only DCQL-relevant fields from the preset, stripping UI/validation extras
        const dcqlInput = {
            credentials: (preset.credentials || []).map((/** @type {any} */ cred) => {
                /** @type {any} */
                const c = { id: cred.id, format: cred.format, meta: cred.meta };
                if (cred.claims) c.claims = cred.claims;
                return c;
            }),
        };

        const result = v.safeParse(dcqlQuerySchema, dcqlInput);
        if (!result.success) {
            this.error = "Malformed predefined DCQL query";
            this.loading = false;
            return;
        }

        // @ts-ignore
        this.credentialAttributes = {};
        this.credentialsList = {};

        this.dcqlQuery = result.output;

        // Build per-scope validations map from credential-level validations
        /** @type {Record<string, any>} */
        const valMap = {};
        if (preset.credentials) {
            for (const cred of preset.credentials) {
                if (cred.validations && cred.validations.length > 0) {
                    valMap[cred.id] = cred.validations;
                }
            }
        }
        this.validations = Object.keys(valMap).length > 0 ? valMap : null;

        await this.sendDcqlQuery();

        this.loading = false;
    },

    /** @param {SubmitEvent} event */
    handleCredentialSelectionForm(event) {
        this.error = null;
        this.loading = true;

        if (!(this.$refs.credentialSelectionForm instanceof HTMLFormElement)) {
            this.error = "Credential Selection form not of type 'HtmlFormElement'";
            return;
        }

        const formData = new FormData(this.$refs.credentialSelectionForm);

        const credential = formData.get("credential")?.toString();
        if (!credential) {
            this.error = "Credential is required";
            return;
        }

        if (!this.credentialsList || !this.credentialsList[credential]) {
            this.error = "Credential is missing or invalid";
            return;
        }

        const chosenCredential = this.credentialsList[credential];

        /** @type {Record<string, (string|null)[]>} */
        const claims = {}
        for (const [label, path] of Object.entries(chosenCredential.attributes['en-US'])) {
            claims[label] = path;
        }

        this.credentialAttributes = {
            id: credential,
            format: chosenCredential.format,
            vct: chosenCredential.vct,
            claims,
            claimTree: buildClaimTree(claims),
        }

        this.loading = false;
    },

    /** @param {'all'|'none'} mode */
    handleAttributesToggle(mode) {
        if (!(this.$refs.fieldsList instanceof HTMLElement)) {
            this.error = "Fields list form not of type 'HTMLElement'";
            return;
        }

        return () => {
            /** @type {NodeListOf<HTMLInputElement>} */
            const inputs = this.$refs.fieldsList.querySelectorAll("input[type='checkbox']");

            for (const input of Array.from(inputs)) {
                input.checked = mode === "all";
            }
        }
    },

    handleResetCancel() {
        this.credentialAttributes = null;
        this.dcqlQuery = null;
        this.presentationDefinition = null;
        this.dcApiVerified = false;
    },

    /** 
     * Handle click on wallet link - close SSE connection for same-device flow
     * This allows the server to detect same-device flow and include redirect_uri
     */
    handleWalletClick() {
        console.log("Wallet link clicked, closing SSE connection for same-device flow");
        if (this.notifyEventSource) {
            this.notifyEventSource.close();
            this.notifyEventSource = null;
        }
    },

    /** @param {SubmitEvent} event */
    async handleAttributesSelectionForm(event) {
        this.error = null;
        this.loading = true;

        if (!this.credentialAttributes) {
            this.error = "Selected attributes list is null";
            return;
        }

        if (!(this.$refs.attributesSelectionForm instanceof HTMLFormElement)) {
            this.error = "Attributes selection form not of type 'HtmlFormElement'";
            return;
        }

        const formData = new FormData(this.$refs.attributesSelectionForm);

        /** @type {DCQLQueryCredential["claims"]} */
        const claims = [];
        for (const field of formData.getAll("attribute[]")) {
            const path = this.credentialAttributes.claims[field.toString()];

            if (!path) continue;

            claims.push({ path });
        }

        // mso_mdoc credentials have no vct - the DCQL equivalent constraint
        // is doctype_value (OpenID4VP 1.0 6.4.1), not vct_values. Sending
        // vct_values for an mdoc credential matches nothing on the wallet
        // side (no mdoc credential has a vct), so the request always comes
        // back empty.
        const meta = this.credentialAttributes.format === "mso_mdoc"
            ? { doctype_value: this.credentialAttributes.vct }
            : { vct_values: [this.credentialAttributes.vct] };

        /** @satisfies {DCQLQueryCredential} */
        const credential = {
            id: this.credentialAttributes.id,
            format: this.credentialAttributes.format,
            meta,
            claims,
        };

        /** @satisfies {DCQLQuery} */
        const dcqlQuery = {
            credentials: [credential],
        };

        const { output: dcql_query, success } = v.safeParse(dcqlQuerySchema, dcqlQuery);
        if (!success) {
            this.error = "Invalid DCQL query";
            return;
        }

        this.dcqlQuery = dcql_query;

        await this.sendDcqlQuery();

        this.loading = false;
    },

    async sendDcqlQuery() {
        console.log("sendDcqlQuery called");
        if (!this.walletInstances) {
            this.error = "Wallet instances list is null";
            return;
        }

        this.dcApiVerified = false;

        try {
            const res = await this.fetchData(
                new URL("/ui/interaction", baseUrl), 
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                        dcql_query: this.dcqlQuery,
                        ...(this.validations ? { validations: this.validations } : {}),
                    })
                },
            );

            this.presentationDefinition = v.parse(presentationDefinitionSchema, res);

            // Configure the DC API polyfill with server-side session info
            configureDCAPI({
                baseUrl: baseUrl.toString(),
                sseUrl: new URL("/ui/notify", baseUrl).toString(),
                webWallets: this.walletInstances,
            });

            // Try native DC API first
            if (await this._tryNativeDCAPI()) return;

            // Fallback: show QR code + wallet links + SSE listener
            this._setupFallbackFlow();
        } catch (error) {
            this.error = `Error during posting of dcql query: ${error}`;
        }
    },

    /**
     * Attempt credential request via native DC API.
     *
     * The authorization_request URI is the same openid4vp://...?client_id=...
     * &request_uri=... deep link used for QR/redirect - NOT itself a valid DC
     * API `request` value for any protocol. requestCredentialFromAuthorizationRequestURI
     * (from @sirosfoundation/dc-api) resolves it into whatever shape the
     * detected protocol actually needs (fetching request_uri for the JWT when
     * required) before calling navigator.credentials.get().
     *
     * @returns {Promise<boolean>} true if handled, false to fall through
     */
    async _tryNativeDCAPI() {
        if (!this.dcApiEnabled) return false;
        if (!isNativeDCAPIAvailable() || !getBestSupportedProtocol()) return false;

        try {
            const abortController = new AbortController();
            this._dcAbort = abortController;

            const result = await requestCredentialFromAuthorizationRequestURI(
                this.presentationDefinition.authorization_request,
                { signal: abortController.signal },
            );
            if (!result) return false;

            // result.data is the WALLET's own DC API response payload
            // (returned directly to this page by navigator.credentials.get(),
            // never over the network) - it can never itself carry a
            // redirect_uri, since that's a property of the VERIFIER's HTTP
            // response, not of the wallet's. Unlike the QR/deep-link flow
            // (where the wallet POSTs its response to response_uri over the
            // network on its own), this page is the only thing that has the
            // response in hand, so it must forward it itself before the
            // verifier's backend ever learns the presentation happened.
            const submission = await this._submitDCAPIResponse(result.data);
            if (submission?.redirect_uri) {
                globalThis.location.href = submission.redirect_uri;
            } else {
                this.dcApiVerified = true;
            }
            return true;
        } catch (err) {
            if (err.name === 'AbortError') return true;
            console.log("DC API not available or failed, falling back to QR/links:", err.message);
            return false;
        }
    },

    /**
     * Forward the wallet's DC API response payload to the verifier's own
     * response_uri (`/verification/oidc-direct_post`) - the exact endpoint a
     * non-DC-API wallet POSTs to directly over the network for the QR/
     * deep-link flow, so this reaches the identical server-side handling
     * (ProcessDirectPost) either way.
     *
     * The payload has one of two shapes depending on the negotiated
     * response_mode: `{ response: "<jwe-compact>" }` for `dc_api.jwt`
     * (encrypted/signed), or `{ vp_token: {...}, state }` for plain
     * `dc_api` - `vp_token` there is itself a JSON object (DCQL query id ->
     * VP), sent JSON-encoded as a single string, matching how the
     * form-encoded direct_post request already carries it for the QR flow.
     *
     * @param {{response?: string, vp_token?: object, state?: string}} data
     * @returns {Promise<{redirect_uri?: string} | null>}
     */
    async _submitDCAPIResponse(data) {
        const body = new URLSearchParams();
        if (data.response) {
            body.set("response", data.response);
        } else if (data.vp_token) {
            body.set("vp_token", JSON.stringify(data.vp_token));
        } else {
            throw new Error("DC API response has neither 'response' nor 'vp_token'");
        }
        if (data.state) body.set("state", data.state);

        const res = await fetch(new URL("/verification/oidc-direct_post", baseUrl), {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body,
        });
        if (!res.ok) {
            const text = await res.text();
            throw new Error(`Failed to submit DC API response: HTTP ${res.status} - ${text}`);
        }
        return res.json().catch(() => null);
    },

    /** Set up QR + wallet links + SSE fallback flow. */
    _setupFallbackFlow() {
        if (!this.notifyEventSource) {
            console.log("Starting SSE notify listener from sendDcqlQuery");
            this.notifyEventSource = setupNotifyListener();
        }

        const presDefURI = new URL(this.presentationDefinition.authorization_request);

        for (const [label, url] of Object.entries(this.walletInstances)) {
            const uri = new URL(url);
            uri.search = presDefURI.search;
            uri.hash = presDefURI.hash;

            if (!this.redirectUris) this.redirectUris = {};
            this.redirectUris[`Open with ${label}`] = uri.toString();
        }
    },

    /**
     * @param {RequestInfo|URL} url 
     * @param {RequestInit} options 
     * @returns {Promise<any>}
     */
    async fetchData(url, options) {
        if (url instanceof URL) url = url.toString();
        const response = await fetch(url, options);
        if (!response.ok) {
            if (response.status === 401) {
                throw new Error("Unauthorized/session expired");
            }
            throw new Error(`HTTP error! status: ${response.status}, url: ${url}`);
        }

        const data = await response.json();
        console.debug(JSON.stringify(data, null, 2));
        return data;
    },
}));

Alpine.start();
