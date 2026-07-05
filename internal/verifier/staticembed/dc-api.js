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
  OID4VP_PROTOCOLS,
  getBestProtocol,
  getUserFriendlyErrorMessage,
  isDCAPIAvailable,
  isProtocolAllowed,
  isProtocolUnsupported,
  isUserCancel,
  requestCredential
};
