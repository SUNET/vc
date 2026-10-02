import Alpine from "alpinejs";
import * as v from "valibot";
import {
    configure as configureDCAPI,
    isNativeDCAPIAvailable,
    getBestSupportedProtocol,
    requestCredentialFromAuthorizationRequestURI,
} from "./dc-api-polyfill.js";
import { groupPresets } from "./preset-helpers.js";
import { claimsForLocale } from "./locale-helpers.js";

/** @typedef {v.InferOutput<typeof credentialAttributesSchema>} CredentialAttributes */
const credentialAttributesSchema = v.object({
    format: v.string(),
    vct: v.string(),
    // nullish, not optional: absent for an older server that only sends "vct",
    // and null for one that emits the field without omitempty. The query
    // builder falls back to [vct] in both cases.
    vct_values: v.nullish(v.array(v.string())),
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
    dc_api_auto_attempt: v.optional(v.boolean(), true),
    // preset_category_order lists every distinct category name in display
    // order - see UIMetadataReply.PresetCategoryOrder's own doc comment for
    // why this can't just be derived by sorting category names client-side.
    preset_category_order: v.optional(v.array(v.string()), []),
    presets: v.optional(v.record(v.string(), v.object({
        label: v.string(),
        category: v.optional(v.string(), ""),
        order: v.optional(v.number(), 0),
        featured: v.optional(v.boolean(), false),
        credentials: v.array(v.object({
            id: v.string(),
            format: v.string(),
            // vct_values (sd-jwt) and doctype_value (mso_mdoc) are mutually
            // exclusive and both optional: which one applies depends on the
            // credential's format (OpenID4VP 1.0 6.4.1). Declaring only
            // vct_values here meant an mdoc preset's doctype_value was
            // silently stripped by the schema before reaching the query.
            meta: v.object({
                vct_values: v.optional(v.array(v.string())),
                doctype_value: v.optional(v.string()),
                // zk_system_type entries are a flat {id, system, ...params}
                // string-keyed object on the wire (ZKSystemTypeSpec's own
                // MarshalJSON flattens params to the top level, no nested
                // "params" key) - v.record(string,string), not a fixed
                // {id, system} shape, so an arbitrary param (e.g.
                // num_attributes, circuit_hash) isn't silently dropped.
                // Without this field declared at all, v.object() stripped
                // it from every parsed preset - the verifier's own
                // zk_system_type was present on the wire but never reached
                // the DCQL query the wallet received, which is
                // indistinguishable from "no ZK system offered" wallet-side.
                zk_system_type: v.optional(v.array(v.record(v.string(), v.string()))),
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
            // zk_system_type (mso_mdoc_zk only) is an array of flat
            // {id, system, ...params} objects - declared explicitly since
            // the catch-all record below only accepts string/string[]
            // values, not array-of-object, and would otherwise reject
            // (not silently drop) this entire query at the
            // v.safeParse(dcqlQuerySchema, ...) gate right before it's
            // sent - "Malformed predefined DCQL query" with no further
            // detail. See the identical fix on metadataResponseSchema's
            // preset meta - same root cause, different validation
            // checkpoint (that one stripped the field silently; this one
            // rejects the whole query instead).
            zk_system_type: v.optional(v.array(v.record(v.string(), v.string()))),
        }),
        // v.intersect validates the object against EVERY member schema, not
        // just "whichever keys aren't already declared above" - confirmed
        // live (both via the deployed error and a local valibot repro):
        // this catch-all record still runs against the ENTIRE meta object,
        // zk_system_type included, so its value union has to independently
        // accept zk_system_type's own array-of-objects shape too, or the
        // intersection fails even though the object schema above already
        // declared and accepted the field.
        v.record(v.string(), v.union([
            v.string(),
            v.array(v.string()),
            v.array(v.record(v.string(), v.string())),
        ])),
    ]),
    claims: v.optional(v.array(v.object({
        path: v.array(v.nullable(v.string())),
    }))),
});

const credentialSetQuerySchema = v.object({
    options: v.array(v.array(v.string())),
    required: v.optional(v.boolean()),
});

/** @typedef {v.InferOutput<typeof dcqlQuerySchema>} DCQLQuery */
const dcqlQuerySchema = v.object({
    credentials: v.array(dcqlQueryCredentialSchema),
    credential_sets: v.optional(v.array(credentialSetQuerySchema)),
});

/** @typedef {v.InferOutput<typeof presentationDefinitionSchema>} PresentationDefinition */
const presentationDefinitionSchema = v.object({
    // Server-generated id for this authorization context. Included in
    // subsequent POSTs (e.g. session-preference) so a fresh tab does not
    // silently overwrite the shared per-origin cookie session and steer the
    // flag onto the wrong request.
    session_id: v.string(),
    qr_code: v.string(),
    // The request_uri channel: QR code, same-device link, polyfill redirect.
    // response_mode direct_post.jwt.
    authorization_request: v.string(),
    // The browser DC API's own request, response_mode dc_api.jwt. Declared
    // here or v.object() strips it before anything can read it - absent
    // whenever the DC API is disabled server-side, hence optional.
    dc_api_authorization_request: v.optional(v.string(), ""),
});

/**
 * Due to bfcache some state will persist across
 * navigation events, so we 'manually' clear it.
 * @see https://developer.mozilla.org/en-US/docs/Glossary/bfcache
 *
 * A hard reload here would abandon any in-flight cross-device wallet scan:
 * the QR the user's phone is still holding is bound to a session_id that
 * would be replaced on the next /ui/interaction. Alpine's init() does NOT
 * re-run on a bfcache restore, so init() installs a pageshow listener
 * (event.persisted) that reruns the resume path - reopens SSE and calls
 * /ui/completion - instead of recreating the authorization context from
 * scratch here.
 */

const baseUrl = new URL(window.location.origin);

// JWT_METADATA_CLAIMS lists SD-JWT infrastructure claims the inline result
// view skips, matching the server-side callback.html renderer in
// httpserver/service.go.
const JWT_METADATA_CLAIMS = new Set([
    "iss", "sub", "iat", "exp", "nbf", "jti", "cnf", "vct", "vct#integrity",
    "status", "_sd", "_sd_alg",
]);

/** @param {string} s */
function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => (
        c === "&" ? "&amp;" :
        c === "<" ? "&lt;" :
        c === ">" ? "&gt;" :
        c === '"' ? "&quot;" :
        "&#39;"
    ));
}

/**
 * Append one or more <tr> rows describing name/value at the given depth.
 * Mirrors renderNode in internal/verifier/httpserver/service.go.
 *
 * @param {string[]} rows
 * @param {string} name
 * @param {any} value
 * @param {number} depth
 */
function renderClaimNode(rows, name, value, depth) {
    const indent = depth * 24;
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
        rows.push(
            `<tr><td style="padding-left:${indent}px;font-weight:600;">${escapeHtml(name)}</td><td></td></tr>`,
        );
        for (const childKey of Object.keys(value).sort()) {
            if (JWT_METADATA_CLAIMS.has(childKey)) continue;
            renderClaimNode(rows, childKey, value[childKey], depth + 1);
        }
        return;
    }
    if (Array.isArray(value)) {
        const parts = [];
        for (const elem of value) {
            if (elem && typeof elem === "object" && !Array.isArray(elem)) {
                const keys = Object.keys(elem);
                if (keys.length === 1 && keys[0] === "...") continue;
            }
            parts.push(String(elem));
        }
        if (parts.length > 0) {
            rows.push(
                `<tr><td style="padding-left:${indent}px;">${escapeHtml(name)}</td><td><code>${escapeHtml(parts.join(", "))}</code></td></tr>`,
            );
        } else {
            rows.push(
                `<tr><td style="padding-left:${indent}px;">${escapeHtml(name)}</td><td><code>[]</code> <em>(element details not disclosed by wallet)</em></td></tr>`,
            );
        }
        return;
    }
    const valStr = String(value);
    if (name === "picture") {
        rows.push(
            `<tr><td style="padding-left:${indent}px;">${escapeHtml(name)}</td><td><img src="data:image/png;base64,${escapeHtml(valStr)}" alt="Picture" style="max-width:120px;max-height:160px;border-radius:4px;"></td></tr>`,
        );
    } else {
        rows.push(
            `<tr><td style="padding-left:${indent}px;">${escapeHtml(name)}</td><td><code>${escapeHtml(valStr)}</code></td></tr>`,
        );
    }
}

/**
 * Deep-clean SD-JWT unresolved array-element markers ({"...": hash}) from
 * credential data, matching cleanUnresolvedMarkersForDisplay in
 * internal/verifier/httpserver/service.go. Used for the "Credential data"
 * JSON pretty-print under the inline result view.
 *
 * @param {any} value
 * @returns {any}
 */
function cleanUnresolvedMarkers(value) {
    if (Array.isArray(value)) {
        const out = [];
        for (const elem of value) {
            if (elem && typeof elem === "object" && !Array.isArray(elem)) {
                const keys = Object.keys(elem);
                if (keys.length === 1 && keys[0] === "...") continue;
            }
            out.push(cleanUnresolvedMarkers(elem));
        }
        return out;
    }
    if (value !== null && typeof value === "object") {
        /** @type {Record<string, any>} */
        const out = {};
        for (const [k, v] of Object.entries(value)) {
            out[k] = cleanUnresolvedMarkers(v);
        }
        return out;
    }
    return value;
}

// SESSION_STORAGE_KEY names the sessionStorage entry that carries the
// server-generated session_id across reloads. sessionStorage (not
// localStorage) so it is tab-scoped and cleared on tab close, matching the
// lifetime of an in-flight wallet interaction.
const SESSION_STORAGE_KEY = "vc.verifier.session_id";
// RESPONSE_CODE_STORAGE_KEY carries the response_code of the last completed
// verification across F5 reloads so the result stays on screen instead of
// snapping back to the preset menu. The server's credential cache is the
// authority (5m TTL); this entry is cleared when the user leaves the result.
const RESPONSE_CODE_STORAGE_KEY = "vc.verifier.response_code";

/** @returns {string} */
function loadStoredSessionID() {
    try {
        return window.sessionStorage.getItem(SESSION_STORAGE_KEY) ?? "";
    } catch {
        return "";
    }
}

/** @param {string} id */
function storeSessionID(id) {
    try {
        if (id) {
            window.sessionStorage.setItem(SESSION_STORAGE_KEY, id);
        }
    } catch {
        // sessionStorage may be blocked (private mode, disabled by policy).
        // Reload survival is unavailable in that case: the cookie is no
        // longer treated as a reuse hint by /ui/interaction, so a reload
        // mints a fresh session rather than rejoining the in-flight one.
    }
}

function clearStoredSessionID() {
    try {
        window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
    } catch {
        // Same as storeSessionID.
    }
}

/** @returns {string} */
function loadStoredResponseCode() {
    try {
        return window.sessionStorage.getItem(RESPONSE_CODE_STORAGE_KEY) ?? "";
    } catch {
        return "";
    }
}

/** @param {string} code */
function storeResponseCode(code) {
    try {
        if (code) {
            window.sessionStorage.setItem(RESPONSE_CODE_STORAGE_KEY, code);
        }
    } catch {
        // sessionStorage may be blocked; the result then only survives
        // within the same page lifetime and an F5 falls back to the menu.
    }
}

function clearStoredResponseCode() {
    try {
        window.sessionStorage.removeItem(RESPONSE_CODE_STORAGE_KEY);
    } catch {
        // Same as storeResponseCode.
    }
}

/**
 * Listen for SSE notifications from the server.
 * When a response_code is received, invoke onRedirect so the caller can
 * decide whether to render the result inline or navigate to the URL.
 *
 * The session_id is passed as a query param so the reloaded tab can rejoin
 * an authorization context even when a concurrent tab has already
 * overwritten the shared cookie. Absent id falls back to the cookie.
 *
 * @param {string | undefined} sessionID
 * @param {(redirectURI: string) => void} onRedirect
 */
function setupNotifyListener(sessionID, onRedirect) {
    console.log("Setting up SSE notify listener");
    const notifyURL = new URL("/ui/notify", baseUrl);
    if (sessionID) {
        notifyURL.searchParams.set("session_id", sessionID);
    }
    const eventSource = new EventSource(notifyURL.toString());

    eventSource.onopen = () => {
        console.log("SSE connection opened");
    };

    eventSource.onmessage = (event) => {
        const data = event.data;
        console.log("SSE message received:", data);

        if (!data || typeof data !== "string" || !data.includes("redirect_uri")) {
            return;
        }
        let redirectURI = "";
        try {
            const parsed = JSON.parse(data);
            if (parsed.redirect_uri) {
                redirectURI = parsed.redirect_uri;
            }
        } catch {
            const match = data.match(/redirect_uri[=:]["']?([^"'\s]+)/);
            if (match && match[1]) {
                redirectURI = match[1];
            }
        }
        if (!redirectURI) return;
        console.log("Received redirect_uri from SSE:", redirectURI);
        eventSource.close();
        onRedirect(redirectURI);
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

    /** @type {boolean} Whether sendDcqlQuery() calls navigator.credentials.get() before rendering the wallet link/QR screen; when false it goes straight to that screen. Separate from dcApiEnabled because an OS-level DC API matcher can reject a format with its own dialog before any JS runs, leaving no failure to catch - see DigitalCredentialsConfig.AutoAttempt. */
    dcApiAutoAttempt: true,

     /** @type {{ id: string; format: string; vct: string; vct_values?: string[]; claims: Record<string, (string|null)[]>; claimTree: ClaimNode[]; } | null} */
    credentialAttributes: null,

    /**
     * @type {Record<string, object>}
     */
    predefinedPresentationDefinitions: {},

    /** @type {string[]} Category display order - see metadataResponseSchema's own doc comment. */
    presetCategoryOrder: [],

    /**
     * @type {{ featured: [string, any][], groups: { category: string, presets: [string, any][] }[] }}
     * The grouped, sorted view the template renders. Derived from
     * predefinedPresentationDefinitions and presetCategoryOrder, and
     * computed once where those are set rather than on every read: the
     * template reads it from three places and Alpine re-evaluates on each
     * reactive update, so a method here re-entried and re-sorted the whole
     * catalog every time. Both inputs are assigned in exactly one place
     * (loadMetadata), which is why this needs no cache key or invalidation.
     */
    groupedPresetData: { featured: [], groups: [] },

    /** @type {boolean} Whether the non-featured/categorized preset groups are expanded. */
    showMorePresets: false,

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

    /** @type {{credential_data: Array<{scope: string, credential: Record<string, any>, claims: any}>} | null}
     * The last completed verification's result, shown inline so the verifier
     * stays on the page instead of navigating to /verification/callback and
     * losing the result on an F5 reload. */
    verificationResult: null,

    /** @type {boolean} True when a stored response_code refers to a result
     * the server no longer has (credential cache TTL expired). */
    verificationExpired: false,

    async init() {
        await this.lookupCredentialsList();

        this.loading = false;

        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });

        // bfcache restore keeps the DOM and JS state but does NOT re-run
        // Alpine init, so the SSE listener we had before the user navigated
        // away is gone and a wallet completion arriving while the page was
        // cached is lost by the non-durable pub/sub bus. On pageshow with
        // event.persisted==true we re-run the resume path: it reconnects
        // SSE and reconciles the server-side completion marker through
        // /ui/completion. The listener itself lives for the document's
        // lifetime, so no cleanup pair is needed.
        globalThis.addEventListener("pageshow", (event) => {
            if (!event.persisted) return;
            void this._handleBFCacheRestore();
        });

        // Restore a previously completed result after an F5. Fetch failure
        // (expired cache) shows the "no longer available" notice rather
        // than silently falling back to the preset menu.
        const storedCode = loadStoredResponseCode();
        if (storedCode) {
            await this.loadVerificationResult(storedCode);
            return;
        }
        // Resume a mid-flow session: either the QR screen the user left
        // behind, or the already-complete response_code if the wallet
        // answered while we were reloading.
        const storedSessionID = loadStoredSessionID();
        if (storedSessionID) {
            await this.resumeFromSessionID(storedSessionID);
        }
    },

    /** Re-run the resume path after a bfcache restore. */
    async _handleBFCacheRestore() {
        const storedCode = loadStoredResponseCode();
        if (storedCode) {
            await this.loadVerificationResult(storedCode);
            return;
        }
        const storedSessionID = loadStoredSessionID();
        if (!storedSessionID) return;
        // Close the SSE connection that outlived the navigation but may be
        // in an inconsistent state; resumeFromSessionID / _setupFallbackFlow
        // reopens one on the restored session_id.
        if (this.notifyEventSource) {
            this.notifyEventSource.close();
            this.notifyEventSource = null;
        }
        await this.resumeFromSessionID(storedSessionID);
    },

    async lookupCredentialsList() {
        const res = await this.fetchData(new URL("/ui/metadata", baseUrl), {});

        const data = v.parse(metadataResponseSchema, res);

        this.credentialsList = data.credentials;
        this.walletInstances = data.supported_wallets;
        this.dcApiEnabled = data.dc_api_enabled;
        this.dcApiAutoAttempt = data.dc_api_auto_attempt;

        // Load presets from backend config
        if (data.presets) {
            this.predefinedPresentationDefinitions = data.presets;
        }
        // preset_category_order is omitempty, so it is absent whenever no
        // preset is categorized - including the featured-but-uncategorized
        // case, which still takes the grouping path below.
        this.presetCategoryOrder = data.preset_category_order ?? [];

        // Grouped once, here, because this is the only place either input
        // changes. The rules live in preset-helpers.js so they can be unit
        // tested - see groupPresets there.
        this.groupedPresetData = groupPresets(
            Object.entries(this.predefinedPresentationDefinitions),
            this.presetCategoryOrder,
        );
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
        // Not attributes['en-US'] directly: a credential whose claims live
        // only under another locale would send no claim paths at all.
        for (const [label, path] of Object.entries(claimsForLocale(chosenCredential.attributes))) {
            claims[label] = path;
        }

        this.credentialAttributes = {
            id: credential,
            format: chosenCredential.format,
            vct: chosenCredential.vct,
            // Carried through so the custom-credential flow builds the same
            // multi-value vct_values the presets do; without it this path
            // silently falls back to [vct] and only presets interoperate.
            //
            // ?? undefined normalizes the schema's legacy null (accepted so a
            // server that emits the field without omitempty doesn't break the
            // page) to the absent form this object's type declares, keeping
            // the strict checkJs contract consistent.
            vct_values: chosenCredential.vct_values ?? undefined,
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
        this.verificationResult = null;
        this.verificationExpired = false;
        clearStoredSessionID();
        clearStoredResponseCode();
    },

    /**
     * Commit the same-device intent before the browser leaves for a web
     * wallet or launches a native wallet via custom scheme. direct_post
     * reads this flag to decide whether to return redirect_uri, and a
     * fire-and-forget fetch here would race the wallet's response: keepalive
     * only guarantees the request goes out, not that the server has
     * persisted it before direct_post reads the auth context. Await it.
     *
     * The POST carries the session_id returned by /ui/interaction so the
     * flag lands on this presentation's authorization context. The server's
     * cookie fallback is per-origin and shared across tabs: without an
     * explicit id, a second tab that opened /ui/interaction after this one
     * would silently claim the cookie and this click would mark the wrong
     * session.
     *
     * On failure, hand the wallet URL to a tab that was opened synchronously
     * from the click, so the popup blocker still sees a live user gesture
     * (transient activation would already be gone after the awaited fetch).
     * The current tab (and its live SSE) survives to deliver the response
     * through the cross-device channel instead.
     *
     * Do NOT close the SSE here: a same-tab navigation tears it down on its
     * own, and a custom-scheme launch leaves the tab open and still needing
     * SSE as a fallback channel to receive the response.
     */
    async handleWalletClick(event) {
        if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
            return;
        }
        event.preventDefault();
        const url = event.currentTarget.href;
        // Opened inside the click so the browser still counts a live user
        // activation when the fallback runs after the awaited fetch.
        // No `noopener`: that feature makes window.open return null and
        // then we would not be able to close or navigate the placeholder.
        // Severed manually below (opener = null) before any navigation.
        const fallbackWindow = globalThis.open("", "_blank");
        try {
            const res = await fetch(new URL("/verification/session-preference", baseUrl).toString(), {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    session_id: this.presentationDefinition?.session_id ?? loadStoredSessionID(),
                    wallet_follows_redirect: true,
                }),
            });
            if (!res.ok) {
                throw new Error(`session-preference returned ${res.status}`);
            }
            if (fallbackWindow && !fallbackWindow.closed) {
                fallbackWindow.close();
            }
            globalThis.location.href = url;
        } catch (err) {
            console.error("Failed to mark same-device flow, opening wallet in a new tab so this page can still redirect", err);
            if (fallbackWindow && !fallbackWindow.closed) {
                try { fallbackWindow.opener = null; } catch { /* cross-origin after nav */ }
                fallbackWindow.location.href = url;
            } else {
                // Popup blocker denied the pre-opened tab; last-resort try
                // (likely blocked too, but worth attempting).
                globalThis.open(url, "_blank", "noopener");
            }
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
        // vct_values carries the credential's canonical vct - the one value
        // ResolveVCTUrls settles on, which the credential body carries and the
        // issuer metadata advertises, so a wallet matching either finds it.
        // Falls back to the single vct for an older server that sends no list.
        const vctValues = this.credentialAttributes.vct_values?.length
            ? this.credentialAttributes.vct_values
            : [this.credentialAttributes.vct];
        const meta = this.credentialAttributes.format === "mso_mdoc"
            ? { doctype_value: this.credentialAttributes.vct }
            : { vct_values: vctValues };

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
            const storedSessionID = loadStoredSessionID();
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
                        ...(storedSessionID ? { session_id: storedSessionID } : {}),
                    })
                },
            );

            this.presentationDefinition = v.parse(presentationDefinitionSchema, res);
            storeSessionID(this.presentationDefinition.session_id);

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
     * The URI used here is the DC API's own, distinct from the one behind
     * the QR code and the link: they differ in response_mode, which has to
     * follow the delivery channel. It is still an
     * openid4vp://...?client_id=...&request_uri=... shape, and NOT itself a
     * valid DC API `request` value for any protocol. requestCredentialFromAuthorizationRequestURI
     * (from @sirosfoundation/dc-api) resolves it into whatever shape the
     * detected protocol actually needs (fetching request_uri for the JWT when
     * required) before calling navigator.credentials.get().
     *
     * @returns {Promise<boolean>} true if handled, false to fall through
     */
    async _tryNativeDCAPI() {
        if (!this.dcApiEnabled) return false;
        if (!this.dcApiAutoAttempt) return false;
        if (!isNativeDCAPIAvailable() || !getBestSupportedProtocol()) return false;

        try {
            const abortController = new AbortController();
            this._dcAbort = abortController;

            // The DC API request, not the link one: response_mode has to
            // follow the delivery channel, and this call is the only channel
            // a dc_api mode is defined for (SUNET/vc#652). Falls back to the
            // link request if the server sent none, which is what an older
            // verifier does - that request carries direct_post.jwt, which a
            // wallet invoked this way can still answer.
            const result = await requestCredentialFromAuthorizationRequestURI(
                this.presentationDefinition.dc_api_authorization_request ||
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
                await this.handleRedirectURI(submission.redirect_uri);
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
     * Forward the wallet's DC API response payload to THIS page's own
     * response_uri (`/verification/direct_post` -
     * VerificationDirectPost/VerificationDirectPostRequest) - the exact
     * endpoint a non-DC-API wallet POSTs to directly over the network for
     * the QR/deep-link flow (`UIInteraction` sets it as `response_uri` on
     * the very same request object regardless of delivery channel), so this
     * reaches identical server-side handling either way. NOT
     * `/verification/oidc-direct_post` - that belongs to a wholly separate
     * flow (`authorize_enhanced.html`'s OIDC RP page), with its own
     * session/state cache namespace; submitting there for a session created
     * via `/ui/interaction` fails with "session not found".
     *
     * This endpoint only ever accepts one shape: `{ response: "<jwe-compact>" }`
     * (`UIInteraction` always requests an encrypted response - see its
     * `response_mode` doc comment, which now mints `dc_api.jwt` whenever DC
     * API is enabled so the wallet actually encrypts). `state` is never
     * submitted alongside the ciphertext; the server recovers it by
     * decrypting the JWE and reading the `state` claim from the plaintext,
     * which is where the session lookup actually happens
     * (`VerificationDirectPost`) - there is no unencrypted `vp_token`/
     * `presentation_submission` fallback shape on this endpoint to forward.
     *
     * @param {{response?: string}} data
     * @returns {Promise<{redirect_uri?: string} | null>}
     */
    async _submitDCAPIResponse(data) {
        if (!data.response) {
            throw new Error("DC API response is missing the encrypted 'response' payload");
        }
        const body = new URLSearchParams();
        body.set("response", data.response);
        // Tells the verifier this came back inside a
        // navigator.credentials.get call, so it recomputes the mdoc session
        // transcript with the DC API handover (origin-bound) rather than the
        // request_uri one (response-URI-bound). The origin itself comes from
        // the verifier's own configuration, not from here.
        body.set("dc_api", "true");

        const res = await fetch(new URL("/verification/direct_post", baseUrl), {
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
            const sessionID = this.presentationDefinition?.session_id;
            this.notifyEventSource = setupNotifyListener(
                sessionID,
                (redirectURI) => { this.handleRedirectURI(redirectURI); },
            );
            // Close the race between /ui/resume (or sendDcqlQuery) reading
            // "pending" and this SSE subscription becoming live. Firing on
            // "open" guarantees the server-side subscribe-before-check
            // ordering: EventSource.open means the GET /ui/notify handler
            // has already called notify.OpenListener (SSE headers are only
            // flushed after that). A publish between /ui/resume returning
            // "pending" and that moment would be lost by the non-durable
            // bus, so /ui/completion covers it; a publish before SSE is
            // live but after /ui/completion returned is still caught
            // because reconnects also fire "open".
            this.notifyEventSource.addEventListener("open", () => {
                void this._reconcileCompletion(sessionID);
            });
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
     * Check /ui/completion for a persisted response_code and, if found,
     * finish the flow the way the SSE redirect would have. Safe to call
     * even when the SSE listener fires first: loadVerificationResult runs
     * once per response_code, and the second caller sees loading flipped
     * off and bails.
     *
     * @param {string | undefined} sessionID
     */
    async _reconcileCompletion(sessionID) {
        if (!sessionID) return;
        const url = new URL("/ui/completion", baseUrl);
        url.searchParams.set("session_id", sessionID);
        let data;
        try {
            const res = await fetch(url.toString(), { credentials: "same-origin" });
            if (!res.ok) return;
            data = await res.json();
        } catch (err) {
            console.error("Failed to reconcile completion", err);
            return;
        }
        if (!data || data.status !== "complete") return;
        const responseCode = typeof data.response_code === "string" ? data.response_code : "";
        if (!responseCode) return;
        console.log("Reconciled lost SSE completion from /ui/completion");
        if (this.notifyEventSource) {
            this.notifyEventSource.close();
            this.notifyEventSource = null;
        }
        storeResponseCode(responseCode);
        clearStoredSessionID();
        await this.loadVerificationResult(responseCode);
    },

    /**
     * React to a redirect_uri delivered by SSE or returned by a DC API
     * submission. For the verifier's own callback URL (both the
     * cross-device SSE flow and the same-device wallet redirect flow point
     * here) the result is fetched and rendered inline so an F5 keeps the
     * user on the result instead of taking them back to the preset menu.
     * Any other URL is treated as an opaque redirect target.
     *
     * @param {string} redirectURI
     */
    async handleRedirectURI(redirectURI) {
        let responseCode = "";
        try {
            // Second arg lets a relative URI (same-origin) still parse.
            const parsed = new URL(redirectURI, baseUrl);
            if (parsed.origin === baseUrl.origin && parsed.pathname.endsWith("/verification/callback")) {
                responseCode = parsed.searchParams.get("response_code") ?? "";
            }
        } catch (err) {
            console.error("Failed to parse redirect_uri", err);
        }

        if (responseCode) {
            storeResponseCode(responseCode);
            clearStoredSessionID();
            await this.loadVerificationResult(responseCode);
            return;
        }

        // Not our callback URL: fall back to a plain navigation so an
        // integrator-supplied redirect target still works.
        clearStoredSessionID();
        globalThis.location.href = redirectURI;
    },

    /**
     * Fetch the verified credential data for responseCode and show it
     * inline. A 404 means the server-side credential cache has expired (or
     * never knew this code); surface it as verificationExpired rather than
     * dropping the user back on the preset menu with no feedback. A
     * transient 5xx (or any other non-2xx) preserves the stored code so a
     * reload can retry - the code is the only key that can bring the
     * completed result back.
     *
     * @param {string} responseCode
     */
    async loadVerificationResult(responseCode) {
        const url = new URL("/ui/result", baseUrl);
        url.searchParams.set("response_code", responseCode);
        let res;
        try {
            res = await fetch(url.toString(), { credentials: "same-origin" });
        } catch (err) {
            console.error("Failed to load verification result", err);
            this.error = `Failed to load verification result: ${err}`;
            return;
        }
        if (!res.ok) {
            console.log("Verification result not available (status", res.status, ")");
            if (res.status === 404 || res.status === 410) {
                clearStoredResponseCode();
                this.verificationExpired = true;
            } else {
                this.error = `Verification result unavailable (status ${res.status})`;
            }
            this.loading = false;
            return;
        }
        try {
            this.verificationResult = await res.json();
        } catch (err) {
            console.error("Failed to parse verification result", err);
            this.error = `Failed to parse verification result: ${err}`;
            return;
        }
        this.loading = false;
        if (this.notifyEventSource) {
            this.notifyEventSource.close();
            this.notifyEventSource = null;
        }
    },

    /**
     * Rebuild the UI from the server's view of a stored session_id. The
     * three live outcomes are: complete (fetch and show the result), pending
     * (restore the QR screen with its original authorization_request and
     * dcql_query so the wallet's outstanding scan still resolves), or
     * unknown/expired (drop the stored id and fall back to the preset menu).
     *
     * Never throws: a network blip here must not block init from rendering
     * the preset menu.
     *
     * @param {string} sessionID
     */
    async resumeFromSessionID(sessionID) {
        const url = new URL("/ui/resume", baseUrl);
        url.searchParams.set("session_id", sessionID);
        let data;
        try {
            const res = await fetch(url.toString(), { credentials: "same-origin" });
            if (!res.ok) {
                // Only drop the stored id when the server authoritatively
                // says it is gone. A transient 5xx keeps it so a reload
                // can retry; the next call either succeeds or sees the
                // id truly expire.
                if (res.status === 404 || res.status === 410) {
                    clearStoredSessionID();
                }
                return;
            }
            data = await res.json();
        } catch (err) {
            console.error("Failed to resume session", err);
            return;
        }
        if (!data || typeof data !== "object") {
            return;
        }
        if (data.status === "complete" && typeof data.response_code === "string" && data.response_code) {
            storeResponseCode(data.response_code);
            clearStoredSessionID();
            await this.loadVerificationResult(data.response_code);
            return;
        }
        if (data.status === "pending" && typeof data.authorization_request === "string" && data.authorization_request) {
            this.restorePendingQRScreen(data);
            return;
        }
        // unknown or expired: no live state to resume to, so drop the
        // stale id and let the preset menu render.
        clearStoredSessionID();
    },

    /**
     * Re-materialize the QR / wallet-link screen from a /ui/resume reply.
     * credentialsList and credentialAttributes are set to the sentinel
     * empty objects handleSelectPredefinedPresentationDefinition uses, so
     * the template's x-if chain picks the QR view - full menu state
     * repopulation happens later when the user presses "Back to menu".
     *
     * @param {any} data
     */
    restorePendingQRScreen(data) {
        this.credentialsList = {};
        // @ts-ignore - sentinel, matches handleSelectPredefinedPresentationDefinition
        this.credentialAttributes = {};
        this.dcqlQuery = data.dcql_query || null;
        this.validations = data.validations || null;
        this.presentationDefinition = {
            session_id: data.session_id,
            qr_code: data.qr_code || "",
            authorization_request: data.authorization_request,
            dc_api_authorization_request: data.dc_api_authorization_request || "",
        };
        storeSessionID(data.session_id);
        if (this.walletInstances) {
            // Needed for a DC API submission to find its way back to this
            // page's response_uri - mirrors sendDcqlQuery's setup. Native
            // DC API is NOT re-attempted here: a reload cannot resume
            // navigator.credentials.get, so we go straight to the fallback.
            configureDCAPI({
                baseUrl: baseUrl.toString(),
                sseUrl: new URL("/ui/notify", baseUrl).toString(),
                webWallets: this.walletInstances,
            });
        }
        this._setupFallbackFlow();
    },

    /**
     * Return to the preset menu after a completed (or expired) verification.
     * Clears all flow-specific state and re-fetches metadata so the preset
     * buttons and credential dropdown repopulate - handleSelectPredefinedPresentationDefinition
     * clears credentialsList and the custom-credential select would otherwise
     * come up empty.
     */
    async handleBackToMenu() {
        clearStoredResponseCode();
        clearStoredSessionID();
        this.verificationResult = null;
        this.verificationExpired = false;
        this.dcApiVerified = false;
        this.credentialAttributes = null;
        this.dcqlQuery = null;
        this.presentationDefinition = null;
        this.redirectUris = null;
        this.validations = null;
        this.error = null;
        if (this.notifyEventSource) {
            this.notifyEventSource.close();
            this.notifyEventSource = null;
        }
        this.loading = true;
        await this.lookupCredentialsList();
        this.loading = false;
    },

    /**
     * Render a server-returned credential map as HTML table rows. Mirrors
     * the server's renderClaimsTree (see httpserver/service.go) for the
     * inline result view - same claim-skip list, same indentation, same
     * picture-as-image special case.
     *
     * Alpine's x-html binds raw HTML into the DOM; every value interpolated
     * here is escaped first with escapeHtml.
     *
     * @param {Record<string, any>} claims
     * @returns {string}
     */
    renderClaimTree(claims) {
        if (!claims || typeof claims !== "object") return "";
        const rows = [];
        for (const k of Object.keys(claims).sort()) {
            if (JWT_METADATA_CLAIMS.has(k)) continue;
            renderClaimNode(rows, k, claims[k], 0);
        }
        return rows.join("");
    },

    /** @param {any} value */
    cleanCredentialForDisplay(value) {
        return cleanUnresolvedMarkers(value);
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
