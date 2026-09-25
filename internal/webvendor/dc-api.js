// Vendored, unmodified, from @sirosfoundation/dc-api v0.7.0
// (npm package dist/dc-api.bundle.js - `npm pack @sirosfoundation/dc-api`).
//
// ONE copy, shared by apigw and verifier. Both services mount this package
// alongside their own staticembed assets, so /static/dc-api.js resolves here
// for both. It used to be vendored separately into each, which drifted: the
// verifier's copy carried a local AbortSignal patch that upstream did not
// have, so the two could not be merged without either losing cancellation or
// propagating an un-upstreamed fork. That patch is now released upstream
// (sirosfoundation/dc-api#22), which is what made one copy possible.
//
//   Library: https://github.com/sirosfoundation/dc-api
// src/protocols.ts
var OID4VP_PROTOCOLS = {
  /** Unsigned request — client_id derived from web-origin */
  UNSIGNED: "openid4vp-v1-unsigned",
  /** Signed request — JAR with single JWS compact serialization */
  SIGNED: "openid4vp-v1-signed",
  /** Multi-signed request — JWS JSON serialization */
  MULTISIGNED: "openid4vp-v1-multisigned",
  /** Legacy protocol string (pre-spec, used by some implementations) */
  LEGACY: "openid4vp"
};
var OID4VP_SPEC_PROTOCOLS = [
  OID4VP_PROTOCOLS.UNSIGNED,
  OID4VP_PROTOCOLS.SIGNED,
  OID4VP_PROTOCOLS.MULTISIGNED
];
var OID4VP_ALL_PROTOCOLS = [
  ...OID4VP_SPEC_PROTOCOLS,
  OID4VP_PROTOCOLS.LEGACY
];
function isOID4VPProtocol(value) {
  return OID4VP_ALL_PROTOCOLS.includes(value);
}
var OID4VCI_PROTOCOLS = {
  /** OpenID4VCI 1.0 */
  V1: "openid4vci-v1"
};
function isOID4VCIProtocol(value) {
  return value === OID4VCI_PROTOCOLS.V1;
}

// src/detect.ts
function isDCAPIAvailable() {
  return typeof DigitalCredential !== "undefined";
}
function isProtocolAllowed(protocol) {
  if (typeof DigitalCredential === "undefined") return false;
  if (typeof DigitalCredential.userAgentAllowsProtocol !== "function") return false;
  return DigitalCredential.userAgentAllowsProtocol(protocol);
}
var DEFAULT_PREFERENCE = [
  OID4VP_PROTOCOLS.SIGNED,
  OID4VP_PROTOCOLS.MULTISIGNED,
  OID4VP_PROTOCOLS.UNSIGNED
];
function getBestProtocol(preference) {
  const candidates = preference ?? DEFAULT_PREFERENCE;
  for (const proto of candidates) {
    if (isProtocolAllowed(proto)) return proto;
  }
  return null;
}
var _WALLET_REGISTRY_GLOBALS = ["DigitalWallets", "WalletCompanion"];
function _canInvokeCreate() {
  try {
    return typeof navigator !== "undefined" && typeof navigator.credentials?.create === "function";
  } catch {
    return false;
  }
}
function _registeredWalletSupports(protocol) {
  for (const name of _WALLET_REGISTRY_GLOBALS) {
    try {
      const registry = globalThis[name];
      if (!registry || typeof registry.supportsProtocol !== "function") continue;
      if (registry.supportsProtocol(protocol) === true) return true;
    } catch {
    }
  }
  return false;
}
function isIssuanceAvailable(protocol = OID4VCI_PROTOCOLS.V1) {
  if (!_canInvokeCreate()) return false;
  try {
    if (isProtocolAllowed(protocol) === true) return true;
  } catch {
  }
  return _registeredWalletSupports(protocol);
}

// src/request.ts
async function requestCredential(protocol, data, options) {
  const dcOptions = {
    digital: {
      requests: [{
        protocol,
        data
      }]
    }
  };
  if (options?.signal) {
    dcOptions.signal = options.signal;
  }
  const credential = await navigator.credentials.get(dcOptions);
  if (!credential) {
    throw new DOMException("No credential received", "NotAllowedError");
  }
  return normalizeCredential(credential, protocol);
}
function normalizeCredential(credential, fallbackProtocol) {
  const dc = credential;
  return {
    protocol: dc.protocol ?? fallbackProtocol,
    data: dc.data ?? credential
  };
}

// src/issue.ts
async function issueCredential(protocol, data, options) {
  const dcOptions = {
    digital: {
      requests: [{
        protocol,
        data
      }]
    }
  };
  if (options?.signal) {
    dcOptions.signal = options.signal;
  }
  const credential = await navigator.credentials.create(dcOptions);
  if (!credential) {
    throw new DOMException("No credential issued", "NotAllowedError");
  }
  return normalizeCredential(credential, protocol);
}

// src/fetcher.ts
function boundFetch(options) {
  const fetchImpl = options?.fetchFn ?? fetch;
  const signal = options?.signal;
  return (url) => signal ? fetchImpl(url, { signal }) : fetchImpl(url);
}

// src/credential-offer.ts
function _offerParams(offer) {
  const q = offer.indexOf("?");
  return new URLSearchParams(q >= 0 ? offer.slice(q + 1) : offer);
}
function _parseOfferJson(json) {
  try {
    return JSON.parse(json);
  } catch (err) {
    throw new TypeError(`Malformed credential offer: 'credential_offer' is not valid JSON (${String(err)})`);
  }
}
function _assertOffer(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Malformed credential offer: expected a JSON object");
  }
  const offer = value;
  if (typeof offer.credential_issuer !== "string" || offer.credential_issuer === "") {
    throw new TypeError("Malformed credential offer: missing required 'credential_issuer'");
  }
  if (!Array.isArray(offer.credential_configuration_ids)) {
    throw new TypeError("Malformed credential offer: missing required 'credential_configuration_ids'");
  }
  if (offer.credential_configuration_ids.length === 0 || !offer.credential_configuration_ids.every((id) => typeof id === "string" && id !== "")) {
    throw new TypeError(
      "Malformed credential offer: 'credential_configuration_ids' must be a non-empty array of non-empty strings"
    );
  }
  return offer;
}
async function _fetchOffer(offerUri, doFetch) {
  const res = await doFetch(offerUri);
  if (!res.ok) {
    throw new Error(`Failed to fetch credential_offer_uri ${offerUri}: HTTP ${res.status}`);
  }
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new TypeError(
      `Malformed credential offer at ${offerUri}: response body is not valid JSON (${String(err)})`
    );
  }
}
async function buildIssuanceRequestData(offer, options) {
  if (typeof offer === "object" && offer !== null) {
    return _assertOffer(offer);
  }
  if (typeof offer !== "string") {
    throw new TypeError(`Cannot build an issuance request from a ${typeof offer}`);
  }
  const trimmed = offer.trim();
  if (trimmed.startsWith("{")) {
    throw new TypeError(
      "Cannot build an issuance request from a raw JSON string: pass the parsed offer object, or an 'openid-credential-offer://?credential_offer=...' URI"
    );
  }
  const params = _offerParams(trimmed);
  if (params.has("credential_offer")) {
    return _assertOffer(_parseOfferJson(params.get("credential_offer") ?? ""));
  }
  if (params.has("credential_offer_uri")) {
    const byReference = params.get("credential_offer_uri") ?? "";
    if (byReference === "") {
      throw new TypeError("Malformed credential offer: 'credential_offer_uri' is empty");
    }
    return _assertOffer(await _fetchOffer(byReference, boundFetch(options)));
  }
  throw new TypeError(
    "Cannot build an issuance request: offer has neither 'credential_offer' nor 'credential_offer_uri'"
  );
}
async function issueCredentialFromOffer(offer, options) {
  const protocol = options?.protocol ?? OID4VCI_PROTOCOLS.V1;
  if (!isIssuanceAvailable(protocol)) return null;
  const data = await buildIssuanceRequestData(offer, options);
  return issueCredential(protocol, data, options);
}

// src/authorization-request.ts
async function buildRequestData(protocol, authorizationRequestUri, options) {
  const doFetch = boundFetch(options);
  const url = new URL(authorizationRequestUri);
  const params = url.searchParams;
  const inlineRequest = params.get("request");
  const requestUri = params.get("request_uri");
  if (protocol === OID4VP_PROTOCOLS.SIGNED || protocol === OID4VP_PROTOCOLS.MULTISIGNED) {
    const jwt = inlineRequest ?? (requestUri ? await _fetchJwt(requestUri, doFetch) : null);
    if (!jwt) {
      throw new Error(
        `Cannot build ${protocol} request data: authorization request has neither 'request' nor 'request_uri'`
      );
    }
    return { request: jwt };
  }
  if (inlineRequest) {
    return _decodeJwtPayload(inlineRequest);
  }
  if (requestUri) {
    const jwt = await _fetchJwt(requestUri, doFetch);
    return _decodeJwtPayload(jwt);
  }
  const data = {};
  for (const [key, value] of params.entries()) {
    if (key === "client_id") continue;
    try {
      data[key] = JSON.parse(value);
    } catch {
      data[key] = value;
    }
  }
  return data;
}
async function _fetchJwt(requestUri, doFetch) {
  const res = await doFetch(requestUri);
  if (!res.ok) {
    throw new Error(`Failed to fetch request_uri ${requestUri}: HTTP ${res.status}`);
  }
  const text = await res.text();
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed === "string") return parsed;
  } catch {
  }
  return text;
}
function _decodeJwtPayload(jwt) {
  const parts = jwt.split(".");
  if (parts.length < 2) {
    throw new Error("Not a valid JWT: expected at least 2 dot-separated parts");
  }
  let base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  return JSON.parse(atob(base64));
}
async function requestCredentialFromAuthorizationRequestURI(authorizationRequestUri, options) {
  const protocol = getBestProtocol(options?.protocolPreference);
  if (!protocol) return null;
  const data = await buildRequestData(protocol, authorizationRequestUri, options);
  return requestCredential(protocol, data, options);
}

// src/oid4vp-response.ts
function extractOID4VPResponse(result) {
  const data = result.data;
  if (data && typeof data.response === "string") {
    return { responseMode: "dc_api.jwt", jwe: data.response };
  }
  if (data && typeof data.vp_token === "object" && data.vp_token !== null) {
    return { responseMode: "dc_api", vpToken: data.vp_token };
  }
  throw new Error(
    'Unrecognized DC API response shape: expected { response: "<jwe>" } (dc_api.jwt response mode) or { vp_token: {...} } (dc_api response mode) per OpenID4VP 1.0 Appendix A'
  );
}
async function requestOID4VPPresentation(authorizationRequestUri, options) {
  const result = await requestCredentialFromAuthorizationRequestURI(authorizationRequestUri, options);
  if (!result) return null;
  return extractOID4VPResponse(result);
}

// src/errors.ts
var ERROR_MESSAGES = {
  NotAllowedError: "You denied the credential request or no wallet is available.",
  NotSupportedError: "Your browser or wallet does not support this credential type.",
  SecurityError: "Security error \u2014 ensure you are on HTTPS.",
  AbortError: "The request was cancelled or timed out.",
  InvalidStateError: "A credential request is already in progress.",
  TypeError: "The credential request data is malformed."
};
var DEFAULT_MESSAGE = "An unexpected error occurred. Please try again.";
function getUserFriendlyErrorMessage(error) {
  if (error instanceof DOMException) {
    return ERROR_MESSAGES[error.name] ?? DEFAULT_MESSAGE;
  }
  if (error instanceof Error) {
    return ERROR_MESSAGES[error.name] ?? DEFAULT_MESSAGE;
  }
  return DEFAULT_MESSAGE;
}
function isUserCancel(error) {
  return error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError");
}
function isProtocolUnsupported(error) {
  return error instanceof DOMException && error.name === "NotSupportedError";
}
export {
  ERROR_MESSAGES,
  OID4VCI_PROTOCOLS,
  OID4VP_ALL_PROTOCOLS,
  OID4VP_PROTOCOLS,
  OID4VP_SPEC_PROTOCOLS,
  buildIssuanceRequestData,
  buildRequestData,
  extractOID4VPResponse,
  getBestProtocol,
  getUserFriendlyErrorMessage,
  isDCAPIAvailable,
  isIssuanceAvailable,
  isOID4VCIProtocol,
  isOID4VPProtocol,
  isProtocolAllowed,
  isProtocolUnsupported,
  isUserCancel,
  issueCredential,
  issueCredentialFromOffer,
  requestCredential,
  requestCredentialFromAuthorizationRequestURI,
  requestOID4VPPresentation
};
