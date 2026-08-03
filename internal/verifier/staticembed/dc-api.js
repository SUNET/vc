// src/protocols.ts
const OID4VP_PROTOCOLS = {
  /** Unsigned request — client_id derived from web-origin */
  UNSIGNED: "openid4vp-v1-unsigned",
  /** Signed request — JAR with single JWS compact serialization */
  SIGNED: "openid4vp-v1-signed",
  /** Multi-signed request — JWS JSON serialization */
  MULTISIGNED: "openid4vp-v1-multisigned",
  /** Legacy protocol string (pre-spec, used by some implementations) */
  LEGACY: "openid4vp"
};
const OID4VP_SPEC_PROTOCOLS = [
  OID4VP_PROTOCOLS.UNSIGNED,
  OID4VP_PROTOCOLS.SIGNED,
  OID4VP_PROTOCOLS.MULTISIGNED
];
const OID4VP_ALL_PROTOCOLS = [
  ...OID4VP_SPEC_PROTOCOLS,
  OID4VP_PROTOCOLS.LEGACY
];
function isOID4VPProtocol(value) {
  return OID4VP_ALL_PROTOCOLS.includes(value);
}
const OID4VCI_PROTOCOLS = {
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
const DEFAULT_PREFERENCE = [
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

// src/authorization-request.ts
// PATCHED (not upstream @sirosfoundation/dc-api v0.5.0): options.signal was
// accepted by requestCredentialFromAuthorizationRequestURI but dropped
// before reaching the request_uri fetch, so an AbortController passed by
// the caller couldn't cancel a slow/hung request_uri fetch. Threaded
// `signal` through buildRequestData/_fetchJwt below. File an upstream fix
// too so the next dc-api bump doesn't reintroduce this.
async function buildRequestData(protocol, authorizationRequestUri, options) {
  const fetchImpl = options?.fetchFn ?? fetch;
  const signal = options?.signal;
  const url = new URL(authorizationRequestUri);
  const params = url.searchParams;
  const inlineRequest = params.get("request");
  const requestUri = params.get("request_uri");
  if (protocol === OID4VP_PROTOCOLS.SIGNED || protocol === OID4VP_PROTOCOLS.MULTISIGNED) {
    const jwt = inlineRequest ?? (requestUri ? await _fetchJwt(requestUri, fetchImpl, signal) : null);
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
    const jwt = await _fetchJwt(requestUri, fetchImpl, signal);
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
async function _fetchJwt(requestUri, fetchImpl, signal) {
  const res = await fetchImpl(requestUri, signal ? { signal } : void 0);
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
  const data = await buildRequestData(protocol, authorizationRequestUri, { fetchFn: options?.fetchFn, signal: options?.signal });
  return requestCredential(protocol, data, options);
}

// src/errors.ts
const ERROR_MESSAGES = {
  NotAllowedError: "You denied the credential request or no wallet is available.",
  NotSupportedError: "Your browser or wallet does not support this credential type.",
  SecurityError: "Security error \u2014 ensure you are on HTTPS.",
  AbortError: "The request was cancelled or timed out.",
  InvalidStateError: "A credential request is already in progress.",
  TypeError: "The credential request data is malformed."
};
const DEFAULT_MESSAGE = "An unexpected error occurred. Please try again.";
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
  buildRequestData,
  getBestProtocol,
  getUserFriendlyErrorMessage,
  isDCAPIAvailable,
  isOID4VCIProtocol,
  isOID4VPProtocol,
  isProtocolAllowed,
  isProtocolUnsupported,
  isUserCancel,
  requestCredential,
  requestCredentialFromAuthorizationRequestURI
};
