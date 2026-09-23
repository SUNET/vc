import Alpine from "alpinejs";
import * as v from "valibot";

// The library's polyfill is vendored alongside this file but deliberately
// NOT installed. Installing it would shim navigator.credentials.create()
// and .get() for the whole page and, on a browser with no DC API at all,
// define a global DigitalCredential of its own — so every other consumer on
// the page would see a DC API the browser does not have, and
// isIssuanceAvailable() below would be reading the polyfill's own wallet
// registry through a DigitalCredential the polyfill invented, rather than
// the browser's native answer. Nothing registers a wallet with it, so that
// costs a page-wide side effect and buys nothing.
//
// It gets installed when there is something for it to route to: a single
// combined bundle carrying the polyfill and the web-wallets registry in one
// module instance (sirosfoundation/dc-api#23). Until then the same-device
// button stays dormant and the QR is the same-device path too.
import { getUserFriendlyErrorMessage, isUserCancel } from "./dc-api.js";
import { credentialOfferData, isIssuanceAvailable, issuanceResult, OID4VCI_PROTOCOL } from "./offers-helpers.js";


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

const CredentialOfferWalletSchema = v.required(v.object({
    name: v.string(),
    uri: v.string(),
}));

/**
 * @typedef {v.InferOutput<typeof CredentialOfferSchema>} CredentialOffer
 */
const CredentialOfferSchema = v.required(v.object({
    name: v.string(),
    id: v.string(),
    // The bare credential_offer=... query string. Every rendering below is
    // this same offer; only the prefix differs.
    offer: v.string(),
    // The opaque, wallet-agnostic by-value deep link.
    uri: v.string(),
    qr: v.object({
        base64_image: v.string(),
        uri: v.string(),
    }),
    wallets: v.record(v.string(), CredentialOfferWalletSchema),
}));

Alpine.data("app", () => ({
    /** @type {Object<string, Object>} Credential types from offers data */
    credentials: null,

    /** @type {CredentialOffer} */
    credentialOffer: null,

    /** @type {boolean} */
    loading: false,

    /**
     * Whether the same-device DC API button is rendered at all. Re-evaluated
     * whenever an offer is loaded, since a wallet extension can install
     * itself after the page has started. See isIssuanceAvailable() in
     * offers-helpers.js for why this is not simply "the browser has the
     * DC API", and why it is false on every browser today.
     * @type {boolean}
     */
    issuanceAvailable: false,

    /** @type {string | null} */
    issuanceStatus: null,

    /** @type {string | null} */
    error: null,

    init() {
        try {
            // Load offers data from the JSON data element
            const offersDataElement = document.getElementById("offersData");
            if (offersDataElement) {
                const offersData = v.parse(OffersLookupSchema, JSON.parse(offersDataElement.textContent));
                this.credentials = offersData.credential_types;
            }
        } catch (err) {
            this.error = "Failed to load credential types: " + err.message;
        }

        this.issuanceAvailable = isIssuanceAvailable();

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

            if (params.has("scope")) {
                this.loadCredentialOffer(params.get("scope"));
            } else {
                this.credentialOffer = null;
                this.error = null;
                this.issuanceStatus = null;
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
     * Handle form submission to select the credential type. No wallet is
     * chosen here: the offer is wallet-independent, and the page renders it
     * three ways once it exists.
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

        // Update hash to trigger credential offer loading
        window.location.hash = `scope=${encodeURIComponent(credential)}`;
    },

    /**
     * Load credential offer data from GET /offers/:scope endpoint
     * @param {string} scope - Credential type scope/ID
     */
    async loadCredentialOffer(scope) {
        try {
            this.error = null;
            this.issuanceStatus = null;
            this.loading = true;
            this.credentialOffer = null;

            const url = `/offers/${encodeURIComponent(scope)}`;

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
            this.issuanceAvailable = isIssuanceAvailable();
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
     * Same-device issuance over the W3C Digital Credentials API. Only ever
     * reachable when issuanceAvailable is true.
     */
    async handleIssueOnThisDevice() {
        this.error = null;
        this.issuanceStatus = null;

        try {
            const data = credentialOfferData(this.credentialOffer.offer);

            const result = await navigator.credentials.create({
                digital: {
                    requests: [{ protocol: OID4VCI_PROTOCOL, data }],
                },
            });

            // create() can resolve with nothing at all. Reporting a handover
            // that did not happen would strand the operator on a page that
            // looks finished, so say plainly that nothing started and leave
            // the QR as the way forward.
            const outcome = issuanceResult(result);
            if ("pending" in outcome) {
                this.error = "No wallet took the issuance request. You can still scan the QR code.";
                return;
            }

            this.issuanceStatus = outcome.status;
        } catch (err) {
            console.error("Error starting issuance over the DC API:", err);
            this.error = isUserCancel(err)
                ? "Issuance was cancelled. You can still scan the QR code."
                : getUserFriendlyErrorMessage(err);
        }
    },

    /**
     * Open the offer directly in one configured wallet.
     * @param {string} uri
     */
    handleOpenInWallet(uri) {
        if (uri) {
            window.location.href = uri;
        }
    },

    /** Return to the credential-type picker. */
    handleReset() {
        window.location.hash = "";
    },
}));

Alpine.start();
