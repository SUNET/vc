/**
 * W3C Digital Credentials API Client for Verifier
 * 
 * Implements browser-based credential presentation using the W3C Digital Credentials API
 * with support for multiple formats (SD-JWT, mdoc) and graceful fallback to QR codes.
 * 
 * Specification: https://wicg.github.io/digital-credentials/
 * OpenID4VP: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 */

/**
 * Check if W3C Digital Credentials API is available in the browser
 * @returns {boolean} True if the API is supported
 */
export function isDigitalCredentialsSupported() {
    return !!(
        navigator.credentials && 
        navigator.credentials.get &&
        window.DigitalCredentialRequestOptions
    );
}

/**
 * Credential format configuration
 */
const CREDENTIAL_FORMATS = {
    SD_JWT: 'vc+sd-jwt',
    DC_SD_JWT: 'dc+sd-jwt',
    MDOC: 'mso_mdoc'
};

/**
 * Digital Credentials API Client
 */
export class DigitalCredentialsClient {
    /**
     * @param {Object} config Configuration options
     * @param {string} config.sessionId Session identifier
     * @param {string} config.baseUrl Base URL of verifier
     * @param {string[]} config.preferredFormats Ordered list of preferred credential formats
     * @param {boolean} config.useJAR Whether to use JWT Authorization Request
     * @param {string} config.responseMode OpenID4VP response mode (dc_api.jwt, direct_post.jwt, direct_post)
     * @param {Function} config.onProgress Progress callback
     * @param {Function} config.onError Error callback
     * @param {Function} config.onSuccess Success callback
     */
    constructor(config) {
        this.sessionId = config.sessionId;
        this.baseUrl = config.baseUrl || window.location.origin;
        this.preferredFormats = config.preferredFormats || [
            CREDENTIAL_FORMATS.SD_JWT,
            CREDENTIAL_FORMATS.DC_SD_JWT,
            CREDENTIAL_FORMATS.MDOC
        ];
        this.useJAR = config.useJAR !== false; // Default to true
        this.responseMode = config.responseMode || 'dc_api.jwt';
        this.onProgress = config.onProgress || (() => {});
        this.onError = config.onError || console.error;
        this.onSuccess = config.onSuccess || (() => {});
    }

    /**
     * Request credential from user's wallet using W3C Digital Credentials API
     * @returns {Promise<void>}
     */
    async requestCredential() {
        try {
            this.onProgress('Checking browser support...');
            
            if (!isDigitalCredentialsSupported()) {
                throw new Error('W3C Digital Credentials API not supported in this browser');
            }

            this.onProgress('Fetching authorization request...');
            
            // Get the authorization request (signed JWT if JAR is enabled)
            const authRequest = await this.fetchAuthorizationRequest();
            
            this.onProgress('Requesting credential from wallet...');
            
            // Request credential using Digital Credentials API
            const credential = await this.invokeDigitalCredentialsAPI(authRequest);
            
            this.onProgress('Submitting credential...');
            
            // Submit the credential response to verifier
            await this.submitCredentialResponse(credential);
            
            this.onSuccess('Credential verified successfully');
            
        } catch (error) {
            this.onError(error);
            throw error;
        }
    }

    /**
     * Fetch authorization request from verifier
     * Returns either a signed JWT (JAR) or plain request object
     * @returns {Promise<string|Object>}
     */
    async fetchAuthorizationRequest() {
        const endpoint = this.useJAR 
            ? `/verification/request-object/${this.sessionId}`
            : `/verification/request/${this.sessionId}`;
        
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            method: 'GET',
            headers: {
                'Accept': this.useJAR 
                    ? 'application/oauth-authz-req+jwt'
                    : 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to fetch authorization request: ${response.status} ${response.statusText}`);
        }

        if (this.useJAR) {
            // Return signed JWT for JAR flow
            return await response.text();
        } else {
            // Return JSON request object for direct parameter flow
            return await response.json();
        }
    }

    /**
     * Invoke W3C Digital Credentials API to request credential from wallet
     * @param {string|Object} authRequest Authorization request (JWT or object)
     * @returns {Promise<DigitalCredential>}
     */
    async invokeDigitalCredentialsAPI(authRequest) {
        // Build the Digital Credentials API request
        const digitalCredentialOptions = {
            digital: {
                providers: [{
                    protocol: 'openid4vp',
                    request: typeof authRequest === 'string' ? authRequest : JSON.stringify(authRequest)
                }]
            }
        };

        try {
            // Request credential from wallet
            const credential = await navigator.credentials.get(digitalCredentialOptions);
            
            if (!credential) {
                throw new Error('No credential received from wallet');
            }

            return credential;
            
        } catch (error) {
            // Handle specific error cases
            if (error.name === 'NotAllowedError') {
                throw new Error('User denied the credential request');
            } else if (error.name === 'NotSupportedError') {
                throw new Error('Wallet does not support the requested credential type');
            } else if (error.name === 'SecurityError') {
                throw new Error('Security error: Credential request blocked');
            }
            throw error;
        }
    }

    /**
     * Submit credential response to verifier
     * @param {DigitalCredential} credential The digital credential from wallet
     * @returns {Promise<void>}
     */
    async submitCredentialResponse(credential) {
        const endpoint = `${this.baseUrl}/verification/direct_post`;
        
        // Extract data from the credential
        const credentialData = credential.data || credential;
        
        // Prepare the submission based on response mode
        let body;
        let contentType;
        
        if (this.responseMode === 'dc_api.jwt' || this.responseMode === 'direct_post.jwt') {
            // For JWT response modes, the wallet returns encrypted/signed JWT
            body = new URLSearchParams({
                response: typeof credentialData === 'string' ? credentialData : JSON.stringify(credentialData),
                state: this.sessionId
            });
            contentType = 'application/x-www-form-urlencoded';
        } else {
            // For direct_post, submit vp_token and presentation_submission
            body = new URLSearchParams({
                vp_token: credentialData.vp_token || credentialData,
                presentation_submission: JSON.stringify(credentialData.presentation_submission || {}),
                state: this.sessionId
            });
            contentType = 'application/x-www-form-urlencoded';
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': contentType
            },
            body: body
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to submit credential: ${response.status} - ${errorText}`);
        }

        // Check if response includes a redirect
        if (response.redirected) {
            window.location.href = response.url;
            return;
        }

        // Handle JSON response
        const result = await response.json();
        if (result.redirect_uri) {
            window.location.href = result.redirect_uri;
        }
    }

    /**
     * Get format capabilities string for presentation definition
     * @returns {Object} Format capabilities object
     */
    getFormatCapabilities() {
        const formats = {};
        
        this.preferredFormats.forEach(format => {
            switch (format) {
                case CREDENTIAL_FORMATS.SD_JWT:
                case CREDENTIAL_FORMATS.DC_SD_JWT:
                    formats[format] = {
                        'sd-jwt_alg_values': ['ES256', 'ES384', 'ES512', 'RS256'],
                        'kb-jwt_alg_values': ['ES256', 'ES384', 'ES512', 'RS256']
                    };
                    break;
                case CREDENTIAL_FORMATS.MDOC:
                    formats[format] = {
                        'alg_values': ['ES256', 'ES384', 'ES512']
                    };
                    break;
            }
        });
        
        return formats;
    }
}

/**
 * Utility: Detect if user is on mobile device
 * @returns {boolean} True if mobile device detected
 */
export function isMobileDevice() {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
}

/**
 * Utility: Generate deep link URL for mobile wallet
 * @param {string} authRequestURI The request_uri for OpenID4VP
 * @param {string} deepLinkScheme Custom URL scheme (e.g., 'eudi-wallet://')
 * @returns {string} Deep link URL
 */
export function generateDeepLink(authRequestURI, deepLinkScheme = 'openid4vp://') {
    return `${deepLinkScheme}?${new URLSearchParams({ request_uri: authRequestURI })}`;
}

/**
 * Utility: Create QR code data URL for fallback
 * @param {string} sessionId Session identifier
 * @param {string} baseUrl Base URL of verifier
 * @returns {string} QR code image URL
 */
export function getQRCodeURL(sessionId, baseUrl = window.location.origin) {
    return `${baseUrl}/qr/${sessionId}`;
}

/**
 * Format detection helper
 * @param {string} credentialType VCT or doctype
 * @returns {string[]} Suitable formats for this credential type
 */
export function detectSuitableFormats(credentialType) {
    // mdoc typically used for ISO/IEC 18013-5 mDL and similar
    if (credentialType.includes('mdl') || credentialType.includes('iso.18013')) {
        return [CREDENTIAL_FORMATS.MDOC, CREDENTIAL_FORMATS.SD_JWT];
    }
    
    // SD-JWT for most verifiable credentials
    return [CREDENTIAL_FORMATS.SD_JWT, CREDENTIAL_FORMATS.DC_SD_JWT, CREDENTIAL_FORMATS.MDOC];
}

/**
 * Error messages mapping for user-friendly display
 */
export const ERROR_MESSAGES = {
    'NotAllowedError': 'You denied the credential request. Please try again if this was a mistake.',
    'NotSupportedError': 'Your wallet does not support this type of credential. Please use a compatible wallet.',
    'SecurityError': 'Security error occurred. Please ensure you are on a secure connection (HTTPS).',
    'NetworkError': 'Network error occurred. Please check your connection and try again.',
    'TimeoutError': 'The request timed out. Please try again.',
    'default': 'An unexpected error occurred. Please try again or use the QR code.'
};

/**
 * Get user-friendly error message
 * @param {Error} error The error object
 * @returns {string} User-friendly error message
 */
export function getUserFriendlyErrorMessage(error) {
    const errorType = error.name || 'default';
    return ERROR_MESSAGES[errorType] || ERROR_MESSAGES.default;
}
