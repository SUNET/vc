/**
 * Verifier DC API integration — OpenID4VP over the W3C Digital Credentials API
 *
 * Imports core DC API utilities from @sirosfoundation/dc-api and adds
 * verifier-specific transport fallbacks (redirect, QR, SSE/poll).
 *
 * Detection:
 *   (a) typeof DigitalCredential !== "undefined"  — DC API exists
 *   (b) DigitalCredential.userAgentAllowsProtocol("openid4vp-v1-unsigned")
 *       — browser allows the openid4vp presentation protocol
 *
 * If a wallet extension shims the DC API transparently, no special
 * handling is needed — the native path works the same way.
 *
 * References:
 *   - W3C Digital Credentials API: https://w3c-fedid.github.io/digital-credentials/
 *   - OpenID4VP Appendix A (DC API profile): https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 *   - CS-007: Credential Presentation via the Digital Credentials API
 *   - Library: https://github.com/sirosfoundation/dc-api
 */

// Re-export core library functions for consumers
import {
    OID4VP_PROTOCOLS,
    isDCAPIAvailable,
    isProtocolAllowed,
    getBestProtocol,
    requestCredential as dcApiRequestCredential,
    getUserFriendlyErrorMessage,
    isUserCancel,
    isProtocolUnsupported,
    ERROR_MESSAGES,
} from '@sirosfoundation/dc-api';

export {
    OID4VP_PROTOCOLS,
    isDCAPIAvailable,
    isProtocolAllowed,
    getUserFriendlyErrorMessage,
    isUserCancel,
    isProtocolUnsupported,
    ERROR_MESSAGES,
};

// ─── Aliases for backward compat ─────────────────────────────────────────────

/** Alias for isDCAPIAvailable (used by existing verifier code) */
export const isNativeDCAPIAvailable = isDCAPIAvailable;

/** Alias for getBestProtocol (used by existing verifier code) */
export const getBestSupportedProtocol = getBestProtocol;

// ─── Mobile detection ────────────────────────────────────────────────────────

/**
 * Detect mobile device from user agent.
 * @returns {boolean}
 */
function isMobileDevice() {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
        navigator.userAgent
    );
}

// ─── Polyfill configuration ─────────────────────────────────────────────────

/**
 * @typedef {Object} PolyfillConfig
 * @property {string}   baseUrl            Verifier origin (default: window.location.origin)
 * @property {string}   [sessionId]        Session identifier for server-side correlation
 * @property {string}   [requestObjectUrl] URL to fetch signed JWT request object
 * @property {string}   [directPostUrl]    URL for wallet direct_post response
 * @property {string}   [qrCodeUrl]        URL to fetch QR code image
 * @property {string}   [pollUrl]          URL to poll for cross-device response
 * @property {string}   [sseUrl]           URL for SSE notifications
 * @property {Record<string,string>} [webWallets] Map of wallet name → wallet URL
 * @property {string}   [deepLinkScheme]   Custom URL scheme (default: "openid4vp://")
 * @property {boolean}  [preferNative]     Try native DC API first (default: true)
 * @property {number}   [pollIntervalMs]   Polling interval in ms (default: 2000)
 * @property {number}   [timeoutMs]        Overall timeout in ms (default: 300000)
 */

/** @type {PolyfillConfig} */
let _config = {
    baseUrl: '',
    deepLinkScheme: 'openid4vp://',
    preferNative: true,
    pollIntervalMs: 2000,
    timeoutMs: 300000,
};

/**
 * Configure the polyfill. Call before using requestCredential().
 * @param {Partial<PolyfillConfig>} config
 */
export function configure(config) {
    _config = { ..._config, ...config };
    if (!_config.baseUrl) {
        _config.baseUrl = window.location.origin;
    }
}

// ─── Core: requestCredential ────────────────────────────────────────────────

/**
 * Request a credential presentation using the DC API surface.
 *
 * Decision tree:
 *   1. Native DC API + openid4vp protocol → use @sirosfoundation/dc-api
 *   2. Native DC API exists but openid4vp fails → polyfill fallback
 *   3. No DC API → polyfill fallback
 *
 * Polyfill fallback:
 *   a. Web wallet popup (if webWallets configured)
 *   b. Same-device redirect (openid4vp:// on mobile)
 *   c. Cross-device QR code + poll/SSE
 *
 * @param {object} openid4vpRequest  The OpenID4VP authorization request object or signed JWT string
 * @param {object} [options]         Additional options
 * @param {AbortSignal} [options.signal]  AbortSignal for cancellation
 * @returns {Promise<{protocol: string, data: unknown}>}  DigitalCredential-shaped response
 */
export async function requestCredential(openid4vpRequest, options = {}) {
    // 1. Try native DC API via the library if available and preferred
    if (_config.preferNative && isDCAPIAvailable()) {
        const protocol = getBestProtocol();

        if (protocol) {
            try {
                // Build data per protocol variant
                let data;
                if (typeof openid4vpRequest === 'string') {
                    data = { request: openid4vpRequest };
                } else {
                    data = openid4vpRequest;
                }

                const result = await dcApiRequestCredential(protocol, data, options);
                return result;
            } catch (err) {
                // NotAllowedError → user cancelled or no wallet, fall through
                if (err.name !== 'NotAllowedError') {
                    throw err;
                }
                // Fall through to polyfill
            }
        }
        // protocol === null → DC API exists but no openid4vp variant allowed
    }

    // 2. Polyfill path — implement OpenID4VP transport ourselves
    return _polyfillRequest(openid4vpRequest, options);
}

// ─── Polyfill fallback path ─────────────────────────────────────────────────

/**
 * Implement OpenID4VP transport when native DC API is unavailable or
 * doesn't support the openid4vp protocol.
 *
 * @param {object|string} openid4vpRequest
 * @param {object} options
 * @returns {Promise<{protocol: string, data: unknown}>}
 */
async function _polyfillRequest(openid4vpRequest, options) {
    // Same-device mobile: redirect to openid4vp:// scheme
    if (isMobileDevice() && _config.deepLinkScheme) {
        return _sameDeviceRedirect(openid4vpRequest, options);
    }

    // Cross-device: wait for the wallet to respond via server-side
    return _crossDeviceWait(options);
}

// ─── Transport: Same-device redirect ────────────────────────────────────────

/**
 * Redirect to openid4vp:// custom scheme for same-device mobile flow.
 * The wallet posts the VP token to the server's response_uri.
 * We wait for the server to notify us via SSE or polling.
 *
 * @param {object|string} openid4vpRequest
 * @param {object} options
 * @returns {Promise<{protocol: string, data: unknown}>}
 */
async function _sameDeviceRedirect(openid4vpRequest, options) {
    let authRequestUri;

    if (typeof openid4vpRequest === 'string') {
        if (_config.requestObjectUrl) {
            const params = new URLSearchParams();
            params.set('client_id', window.location.origin);
            params.set('request_uri', _config.requestObjectUrl);
            authRequestUri = `${_config.deepLinkScheme}?${params.toString()}`;
        } else {
            const params = new URLSearchParams();
            params.set('request', openid4vpRequest);
            authRequestUri = `${_config.deepLinkScheme}?${params.toString()}`;
        }
    } else {
        const params = new URLSearchParams();
        for (const [key, value] of Object.entries(openid4vpRequest)) {
            if (value !== undefined && value !== null) {
                params.set(key, typeof value === 'object' ? JSON.stringify(value) : String(value));
            }
        }
        authRequestUri = `${_config.deepLinkScheme}?${params.toString()}`;
    }

    window.location.href = authRequestUri;
    return _crossDeviceWait(options);
}

// ─── Transport: Cross-device wait (SSE / poll) ─────────────────────────────

/**
 * Wait for the server to signal that the wallet has responded.
 * Uses SSE if sseUrl is configured, otherwise polls pollUrl.
 *
 * @param {object} options
 * @returns {Promise<{protocol: string, data: unknown}>}
 */
function _crossDeviceWait(options) {
    if (_config.sseUrl) {
        return _waitViaSSE(options);
    }
    if (_config.pollUrl) {
        return _waitViaPoll(options);
    }
    return Promise.reject(
        new Error('No SSE or poll URL configured for cross-device flow'),
    );
}

/**
 * Wait for server notification via SSE.
 * @param {object} options
 * @returns {Promise<{protocol: string, data: unknown}>}
 */
function _waitViaSSE(options) {
    return new Promise((resolve, reject) => {
        const eventSource = new EventSource(_config.sseUrl);

        const timeout = setTimeout(() => {
            cleanup();
            reject(new DOMException('Timeout waiting for wallet response', 'AbortError'));
        }, _config.timeoutMs);

        function onMessage(event) {
            const data = event.data;
            if (!data || typeof data !== 'string') return;

            try {
                const parsed = JSON.parse(data);
                if (parsed.redirect_uri) {
                    cleanup();
                    resolve({
                        protocol: 'openid4vp',
                        data: { redirect_uri: parsed.redirect_uri },
                    });
                }
            } catch {
                const match = data.match(/redirect_uri[=:]["']?([^"'\s]+)/);
                if (match && match[1]) {
                    cleanup();
                    resolve({
                        protocol: 'openid4vp',
                        data: { redirect_uri: match[1] },
                    });
                }
            }
        }

        function onError() {
            // SSE reconnects automatically; only reject on abort
        }

        function onAbort() {
            cleanup();
            reject(new DOMException('Request aborted', 'AbortError'));
        }

        function cleanup() {
            clearTimeout(timeout);
            eventSource.close();
            if (options.signal) {
                options.signal.removeEventListener('abort', onAbort);
            }
        }

        eventSource.onmessage = onMessage;
        eventSource.onerror = onError;
        if (options.signal) {
            options.signal.addEventListener('abort', onAbort, { once: true });
        }
    });
}

/**
 * Wait for server notification via polling.
 * @param {object} options
 * @returns {Promise<{protocol: string, data: unknown}>}
 */
function _waitViaPoll(options) {
    return new Promise((resolve, reject) => {
        const deadline = Date.now() + _config.timeoutMs;
        let timer;

        async function poll() {
            if (Date.now() > deadline) {
                reject(new DOMException('Timeout waiting for wallet response', 'AbortError'));
                return;
            }

            try {
                const response = await fetch(_config.pollUrl);
                if (response.ok) {
                    const data = await response.json();
                    if (data.status === 'code_issued' || data.status === 'completed') {
                        resolve({
                            protocol: 'openid4vp',
                            data,
                        });
                        return;
                    }
                    if (data.status === 'failed' || data.status === 'error') {
                        reject(new Error(data.error || 'Verification failed'));
                        return;
                    }
                }
            } catch {
                // Network error — retry
            }

            timer = setTimeout(poll, _config.pollIntervalMs);
        }

        function onAbort() {
            clearTimeout(timer);
            reject(new DOMException('Request aborted', 'AbortError'));
        }

        if (options.signal) {
            options.signal.addEventListener('abort', onAbort, { once: true });
        }

        poll();
    });
}

// ─── Verifier helpers ───────────────────────────────────────────────────────

/**
 * Get the configured QR code image URL, if available.
 * @returns {string|null}
 */
export function getQRCodeUrl() {
    return _config.qrCodeUrl || null;
}

/**
 * Get the configured deep link URI for same-device flow.
 * @param {string} authorizationRequest  The authorization_request URI from the server
 * @returns {string}
 */
export function getDeepLinkUrl(authorizationRequest) {
    const presDefURI = new URL(authorizationRequest);
    return `${_config.deepLinkScheme || 'openid4vp://'}${presDefURI.search}${presDefURI.hash}`;
}

/**
 * Build web wallet URLs from configured wallets + authorization request.
 * @param {string} authorizationRequest  The authorization_request URI from the server
 * @returns {Record<string, string>}  Map of wallet label → invocation URL
 */
export function getWebWalletUrls(authorizationRequest) {
    if (!_config.webWallets) return {};
    const presDefURI = new URL(authorizationRequest);
    const urls = {};
    for (const [label, baseUrl] of Object.entries(_config.webWallets)) {
        const uri = new URL(baseUrl);
        uri.search = presDefURI.search;
        uri.hash = presDefURI.hash;
        urls[`Open with ${label}`] = uri.toString();
    }
    return urls;
}
