import Alpine from "alpinejs";
import * as v from "valibot";


const CredentialSchema = v.object({
  name: v.string(),
  description: v.string()
});

/**
 * @typedef {v.InferOutput<typeof OffersLookupSchema>} OffersLookup
 */
const OffersLookupSchema = v.required(v.object({
    credential_types: v.record(v.string(), CredentialSchema),
    wallets: v.record(v.string(), v.string())
}))

/**
 * @typedef {v.InferOutput<typeof CredentialOfferSchema>} CredentialOffer
 */
const CredentialOfferSchema = v.required(v.object({
    name: v.string(),
    id: v.string(),
    qr: v.object({
        base64_image: v.string(),
        uri: v.string(),
    }),
}));

Alpine.data("app", () => ({
    /** @type {Object<string, Object>} Credential types from offers data */
    credentials: null,

    /** @type {Object<string, string>} Wallets from offers data */
    wallets: null,

    /** @type {CredentialOffer} */
    credentialOffer: null,

    /** @type {boolean} */
    loading: false,

    /** @type {boolean} */
    opaque: false,

    /** @type {string | null} */
    error: null,

    init() {
        try {
            // Load offers data from the JSON data element
            const offersDataElement = document.getElementById("offersData");
            if (offersDataElement) {
                const offersData = JSON.parse(offersDataElement.textContent);
                this.credentials = offersData.credential_types;
                this.wallets = offersData.wallets;
            }
        } catch (err) {
            this.error = "Failed to load credential types: " + err.message;
        }

        // Setup error watcher
        this.$watch("error", (newVal) => {
            if (typeof newVal === "string") {
                console.error(`Error: ${newVal}`);
            }
        });

        // Handle initial hash and listen for changes
        this.handleHashState();
    },

    handleHashState() {
        const processHash = (hash) => {
            const params = new URLSearchParams(hash.slice(1));

            if (params.has("scope") && params.has("wallet_id")) {
                const scope = params.get("scope");
                const walletId = params.get("wallet_id");
                this.loadCredentialOffer(scope, walletId);
            } else {
                this.credentialOffer = null;
                this.error = null;
            }
        };

        // Process initial hash
        processHash(location.hash);

        // Listen for hash changes
        addEventListener("hashchange", () => {
            processHash(location.hash);
        });
    },

    /**
     * Handle form submission to select credential and wallet
     * @param {SubmitEvent} event 
     */
    async handleOffersForm(event) {
        event.preventDefault();
        this.error = null;

        if (!(this.$refs.offersForm instanceof HTMLFormElement)) {
            this.error = "Offers form not found";
            return;
        }

        const formData = new FormData(this.$refs.offersForm);

        const credential = formData.get("credential");
        if (!credential || typeof credential !== "string") {
            this.error = "Credential is required";
            return;
        }

        if (this.opaque) {
            window.location.hash = `scope=${encodeURIComponent(credential)}&wallet_id=opaque`;
            return;
        }

        const wallet = formData.get("wallet");
        if (!wallet || typeof wallet !== "string") {
            this.error = "Wallet is required";
            return;
        }

        // Update hash to trigger credential offer loading
        window.location.hash = `scope=${encodeURIComponent(credential)}&wallet_id=${encodeURIComponent(wallet)}`;
    },

    /**
     * Load credential offer data from GET /offers/:scope/:wallet_id endpoint
     * @param {string} scope - Credential type scope/ID
     * @param {string} walletId - Wallet ID
     */
    async loadCredentialOffer(scope, walletId) {
        try {
            this.error = null;
            this.loading = true;
            this.credentialOffer = null;

            const url = `/offers/${encodeURIComponent(scope)}/${encodeURIComponent(walletId)}`;

            const res = await fetch(url);
            if (!res.ok) {
                if (res.status === 404) {
                    this.error = "Credential offer not found";
                } else {
                    this.error = `Failed to fetch credential offer: ${res.statusText}`;
                }
                return;
            }

            const jsonData = await res.json();

            const data = v.parse(CredentialOfferSchema, jsonData);
            this.credentialOffer = data;
        } catch (err) {
            console.error("Error loading credential offer:", err);
            this.error = err instanceof Error ? err.message : String(err);
            this.credentialOffer = null;
        } finally {
            this.loading = false;
        }
    },

    /**
     * Proceed with credential offer by opening wallet redirect URI
     */
    handleCredentialOfferProceed() {
        if (this.credentialOffer?.qr?.uri) {
            window.location.href = this.credentialOffer.qr.uri;
        }
    }
}));

Alpine.start();
