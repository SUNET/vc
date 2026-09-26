import Alpine from "alpinejs";
import * as v from "valibot";

// The DC API polyfill and the web-wallet registry, in ONE module instance
// (@sirosfoundation/dc-api /full). Installing them lets a web wallet register
// itself through window.DigitalWallets and be found by the
// navigator.credentials.create() call below.
//
// It must be the combined bundle: the library's separate polyfill and
// web-wallets bundles each inline their own copy of the wallet registry, so a
// wallet registered through one is invisible to the other's create() shim
// (sirosfoundation/dc-api#23, fixed in 0.7.0).
//
// isIssuanceAvailable() is the library's own, and it is asked AFTER the
// install on purpose: installing shims
// DigitalCredential.userAgentAllowsProtocol to answer from the polyfill's
// registry, which is exactly what we want it to report once a wallet has
// registered. It still returns false - and the button still does not render -
// until one actually does.
import { installPolyfill, enableWebWallets } from "./dc-api-full.js";
import { getUserFriendlyErrorMessage, isIssuanceAvailable } from "./dc-api.js";
import { credentialOfferData, issuanceResult, OID4VCI_PROTOCOL } from "./offers-helpers.js";


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
     * itself after the page has started. The library's
     * isIssuanceAvailable() answers "can openid4vci-v1 actually be
     * fulfilled", not "does this browser have the DC API" - so it stays
     * false, and the button stays hidden, until a wallet registers.
     * @type {boolean}
     */
    issuanceAvailable: false,

    /** @type {string | null} */
    issuanceStatus: null,

    /** @type {string | null} */
    copyStatus: null,

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

        try {
            // If the page carries an external WalletCompanion/DigitalWallets
            // registry that already advertises openid4vci-v1, do NOT install
            // our polyfill. The polyfill replaces navigator.credentials.create
            // with a shim that only searches its private _wallets list, and
            // enableWebWallets() early-returns without populating that list
            // when an external companion exists - so with the shim installed
            // the shown button always rejects with NotAllowedError. Skipping
            // the install leaves the external registry's own create() path in
            // place, which isIssuanceAvailable() will still report available.
            const externalCompanionOwnsProtocol =
                typeof globalThis.WalletCompanion?.supportsProtocol === "function" && globalThis.WalletCompanion.supportsProtocol(OID4VCI_PROTOCOL) === true ||
                typeof globalThis.DigitalWallets?.supportsProtocol === "function" && globalThis.DigitalWallets.supportsProtocol(OID4VCI_PROTOCOL) === true;
            if (!externalCompanionOwnsProtocol) {
                installPolyfill();
                enableWebWallets();
            }
        } catch (err) {
            // A page that cannot install the shim simply has no same-device
            // path; the QR is unaffected, so do not fail the whole component.
            console.warn("DC API polyfill not installed:", err);
        }

        this.issuanceAvailable = isIssuanceAvailable(OID4VCI_PROTOCOL);

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
            this.issuanceAvailable = isIssuanceAvailable(OID4VCI_PROTOCOL);
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
            // Deliberately NOT branching on isUserCancel(): it is true for
            // every NotAllowedError, and the polyfill raises that for a
            // blocked popup, for no provider supporting the protocol, and
            // for any error the wallet itself reports - not just for a user
            // who closed the window. Claiming "you cancelled" for a popup
            // the browser blocked sends the operator looking in the wrong
            // place. The library's own message for NotAllowedError already
            // hedges honestly ("You denied the credential request or no
            // wallet is available."), so use it and point back at the QR.
            this.error = `${getUserFriendlyErrorMessage(err)} You can still scan the QR code.`;
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

    /** Copy the opaque credential-offer URI to the clipboard. */
    async handleCopyOffer() {
        const uri = this.credentialOffer?.qr?.uri;
        if (!uri) {
            return;
        }
        try {
            await navigator.clipboard.writeText(uri);
            this.copyStatus = "Copied!";
        } catch (err) {
            console.error("Error copying credential offer:", err);
            this.copyStatus = "Copy failed";
        }
        setTimeout(() => { this.copyStatus = null; }, 2000);
    },

    /** Return to the credential-type picker. */
    handleReset() {
        window.location.hash = "";
    },
}));

Alpine.start();
