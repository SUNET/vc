import Alpine from "alpinejs";
import * as v from "valibot";

/** @typedef {v.InferOutput<typeof credentialAttributesSchema>} CredentialAttributes */
const credentialAttributesSchema = v.object({
    vct: v.string(),
    attributes: v.record(
        v.string(),
        v.record(
            v.string(),
            v.array(v.string()),
        ),
    ),
});

/** @typedef {v.InferOutput<typeof credentialsList>} CredentialsList */
const credentialsList = v.record(
    v.string(),
    credentialAttributesSchema,
);

/** @typedef {v.InferOutput<typeof metadataResponseSchema>} MetadataResponse */
const metadataResponseSchema = v.object({
    credentials: credentialsList,
    supported_wallets: v.record(v.string(), v.string()),
    presets: v.optional(v.record(v.string(), v.object({
        label: v.string(),
        credentials: v.array(v.object({
            id: v.string(),
            format: v.string(),
            meta: v.object({
                vct_values: v.array(v.string()),
            }),
            claims: v.optional(v.array(v.object({
                path: v.array(v.string()),
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
    format: v.union([
        v.literal("dc+sd-jwt"),
    ]),
    meta: v.intersect([
        v.object({
            vct_values: v.array(v.string()),
        }),
        v.record(v.string(), v.union([v.string(), v.array(v.string())])),
    ]),
    claims: v.optional(v.array(v.object({
        path: v.array(v.string()),
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

     /** @type {{ id: string; vct: string; claims: Record<string, string[]>; } | null} */
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

        /** @type {Record<string, string[]>} */
        const claims = {}
        for (const [label, path] of Object.entries(chosenCredential.attributes['en-US'])) {
            claims[label] = path;
        }

        this.credentialAttributes = {
            id: credential,
            vct: chosenCredential.vct,
            claims,
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

        /** @satisfies {DCQLQueryCredential} */
        const credential = {
            id: this.credentialAttributes.id,
            format: "dc+sd-jwt",
            meta: {
                vct_values: [this.credentialAttributes.vct]
            },
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
                        ...(this.validations && { validations: this.validations }),
                    })
                },
            );

            // Start SSE listener AFTER interaction call sets session_id
            if (!this.notifyEventSource) {
                console.log("Starting SSE notify listener from sendDcqlQuery");
                this.notifyEventSource = setupNotifyListener();
                console.log("SSE notify listener started, eventSource:", this.notifyEventSource);
            }

            this.presentationDefinition = v.parse(presentationDefinitionSchema, res);

            const presDefURI = new URL(this.presentationDefinition.authorization_request);

            for (const [label, url] of Object.entries(this.walletInstances)) {
                const uri = new URL(url);

                uri.search = presDefURI.search
                uri.hash = presDefURI.hash

                if (!this.redirectUris) this.redirectUris = {};

                this.redirectUris[`Open with ${label}`] = uri.toString();
            }
        } catch (error) {
            this.error = `Error during posting of dcql query: ${error}`;
            return;
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
