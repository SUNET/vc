// Vendored from @sirosfoundation/dc-api v0.6.0
// (npm package dist/dc-api-polyfill.bundle.js — `npm pack @sirosfoundation/dc-api`).
//
// This is the library's own polyfill: it shims navigator.credentials.get()
// AND navigator.credentials.create(), so an openid4vci-v1 issuance request
// can be fulfilled by a wallet registered with THIS module instance through
// the registerWallet() it exports. It neither defines nor reads
// window.DigitalWallets — that global belongs to the library's separate
// web-wallets bundle, which inlines its own copy of this file and therefore
// its own registry, so a wallet registered there is invisible to the
// create() shim here (sirosfoundation/dc-api#23).
//
// offers.js deliberately does NOT install this. Installing it rebinds
// navigator.credentials.{get,create} page-wide and replaces
// DigitalCredential.userAgentAllowsProtocol with a shim answering from the
// registry above — fabricating a global DigitalCredential outright when the
// browser has none — which would make the page's availability gate report
// the polyfill's state while claiming to report the browser's.
//
// Nothing in this repo shims navigator.credentials.* itself — that belongs
// in the library (same rule as the verifier's DC API support).
//
// PATCHED (not upstream v0.6.0): the library's bundle step rewrites every
// top-level `var` to `const` (`sed -i 's/^var /const /g'` in its package.json
// "bundle" script), which breaks the six module-level bindings the polyfill
// reassigns — installPolyfill() threw "TypeError: Assignment to constant
// variable." before reaching `_installed = true`. The six declarations below
// are `let` again; nothing else is changed. Fixed upstream in
// sirosfoundation/dc-api#21, which removes the `sed` rewrite outright and
// adds a test that rebuilds and invokes each bundle; drop this patch and
// re-vendor once that releases. (#20 is the issuance API issue #21 closes,
// not the bundle bug.)
//
//   Library: https://github.com/sirosfoundation/dc-api
//
// src/polyfill.ts
const _wallets = [];
let _installed = false;
let _originalGet = null;
let _originalCreate = null;
let _originalUAP = null;
let _polyfillCreatedDC = false;
let _opts = {
  timeoutMs: 3e5,
  preferNative: true,
  popupFeatures: "popup=yes,width=480,height=700"
};
function registerWallet(wallet) {
  const idx = _wallets.findIndex((w) => w.id === wallet.id);
  if (idx >= 0) _wallets[idx] = wallet;
  else _wallets.push(wallet);
}
function unregisterWallet(walletId) {
  const idx = _wallets.findIndex((w) => w.id === walletId);
  if (idx >= 0) _wallets.splice(idx, 1);
}
function getRegisteredWallets() {
  return [..._wallets];
}
function installPolyfill(options) {
  if (_installed) return;
  _opts = { ..._opts, ...options };
  _originalGet = navigator.credentials.get.bind(navigator.credentials);
  navigator.credentials.get = _polyfillGet;
  _originalCreate = navigator.credentials.create.bind(navigator.credentials);
  navigator.credentials.create = _polyfillCreate;
  _shimUserAgentAllowsProtocol();
  _installed = true;
}
function uninstallPolyfill() {
  if (!_installed) return;
  if (_originalGet) {
    navigator.credentials.get = _originalGet;
    _originalGet = null;
  }
  if (_originalCreate) {
    navigator.credentials.create = _originalCreate;
    _originalCreate = null;
  }
  _restoreUserAgentAllowsProtocol();
  _installed = false;
}
function isPolyfillInstalled() {
  return _installed;
}
function _polyfillProtocols() {
  const s = /* @__PURE__ */ new Set();
  for (const w of _wallets) {
    for (const p of w.protocols) s.add(p);
  }
  return s;
}
function _shimUserAgentAllowsProtocol() {
  if (typeof DigitalCredential === "undefined") {
    globalThis.DigitalCredential = {
      userAgentAllowsProtocol: (protocol) => _polyfillProtocols().has(protocol)
    };
    _originalUAP = null;
    _polyfillCreatedDC = true;
  } else {
    _originalUAP = DigitalCredential.userAgentAllowsProtocol ?? null;
    DigitalCredential.userAgentAllowsProtocol = (protocol) => {
      if (_polyfillProtocols().has(protocol)) return true;
      return _originalUAP?.(protocol) ?? false;
    };
    _polyfillCreatedDC = false;
  }
}
function _restoreUserAgentAllowsProtocol() {
  if (_polyfillCreatedDC) {
    delete globalThis.DigitalCredential;
    _polyfillCreatedDC = false;
  } else if (_originalUAP) {
    DigitalCredential.userAgentAllowsProtocol = _originalUAP;
    _originalUAP = null;
  }
}
async function _polyfillGet(options) {
  const requests = options?.digital?.requests;
  if (!requests || requests.length === 0) {
    return _originalGet(options);
  }
  if (_opts.preferNative) {
    const nativeResult = await _tryNative(requests, options);
    if (nativeResult) return nativeResult;
  }
  const match = _matchWallet(requests);
  if (!match) {
    throw new DOMException(
      "No digital credential provider supports the requested protocol",
      "NotAllowedError"
    );
  }
  const response = await _invokeWalletPopup(match.wallet, match.request);
  return _toCredential(match.request.protocol, response);
}
async function _tryNative(requests, options) {
  const nativeSupported = requests.filter((r) => _nativeSupports(r.protocol));
  if (nativeSupported.length === 0) return null;
  try {
    const nativeOpts = { ...options, digital: { requests: nativeSupported } };
    const result = await _originalGet(nativeOpts);
    if (result) return result;
  } catch (err) {
    if (err.name !== "NotSupportedError" && err.name !== "NotAllowedError") {
      throw err;
    }
  }
  return null;
}
function _nativeSupports(protocol) {
  if (!_originalUAP) return false;
  return _originalUAP(protocol);
}
function _matchWallet(requests) {
  for (const req of requests) {
    const w = _wallets.find((w2) => w2.protocols.includes(req.protocol));
    if (w) return { wallet: w, request: req };
  }
  return null;
}
async function _invokeWalletPopup(wallet, request) {
  const requestId = crypto.randomUUID();
  const url = _buildUrl(wallet, request, requestId);
  const walletOrigin = new URL(wallet.url).origin;
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new DOMException("Wallet response timeout", "AbortError"));
    }, _opts.timeoutMs);
    const popup = window.open(url, "_blank", _opts.popupFeatures);
    if (!popup) {
      clearTimeout(timeout);
      reject(new DOMException("Popup blocked", "NotAllowedError"));
      return;
    }
    const closePoll = setInterval(() => {
      if (popup.closed) {
        cleanup();
        reject(new DOMException("User closed wallet", "NotAllowedError"));
      }
    }, 500);
    function onMessage(event) {
      if (event.source !== popup) return;
      if (event.data?.type === "WC_ORIGIN_CHECK" && event.data.requestId === requestId) {
        popup.postMessage({ type: "WC_ORIGIN_ACK", requestId }, walletOrigin);
        return;
      }
      if (event.data?.type === "WC_WALLET_RESPONSE" && event.data.requestId === requestId) {
        if (event.origin !== walletOrigin) return;
        cleanup();
        if (event.data.error) {
          reject(new DOMException(event.data.error, "NotAllowedError"));
        } else {
          resolve(event.data.response);
        }
      }
    }
    function cleanup() {
      clearTimeout(timeout);
      clearInterval(closePoll);
      window.removeEventListener("message", onMessage);
      try {
        popup?.close();
      } catch {
      }
    }
    window.addEventListener("message", onMessage);
  });
}
function _buildUrl(wallet, request, requestId) {
  const url = new URL(wallet.url);
  url.searchParams.set("request_id", requestId);
  url.searchParams.set("protocol", request.protocol);
  url.searchParams.set("client_id", window.location.origin);
  const data = request.data;
  if (!data) return url.toString();
  if (typeof data.request === "string") {
    url.hash = data.request;
    return url.toString();
  }
  for (const [key, value] of Object.entries(data)) {
    if (value === void 0 || value === null) continue;
    const serialized = typeof value === "object" ? JSON.stringify(value) : String(value);
    url.searchParams.set(key, serialized);
  }
  return url.toString();
}
async function _polyfillCreate(options) {
  const requests = options?.digital?.requests;
  if (!requests || requests.length === 0) {
    return _originalCreate(options);
  }
  if (_opts.preferNative) {
    const nativeSupported = requests.filter((r) => _nativeSupports(r.protocol));
    if (nativeSupported.length > 0) {
      try {
        const nativeOpts = { ...options, digital: { requests: nativeSupported } };
        const result = await _originalCreate(nativeOpts);
        if (result) return result;
      } catch (err) {
        if (err.name !== "NotSupportedError" && err.name !== "NotAllowedError") {
          throw err;
        }
      }
    }
  }
  const match = _matchWallet(requests);
  if (!match) {
    throw new DOMException(
      "No digital credential provider supports the requested issuance protocol",
      "NotAllowedError"
    );
  }
  const response = await _invokeWalletPopup(match.wallet, match.request);
  return _toCredential(match.request.protocol, response);
}
function _toCredential(protocol, data) {
  const cred = {
    type: "digital",
    id: "",
    protocol,
    data,
    toJSON() {
      return { type: "digital", protocol, data };
    }
  };
  return cred;
}
export {
  getRegisteredWallets,
  installPolyfill,
  isPolyfillInstalled,
  registerWallet,
  uninstallPolyfill,
  unregisterWallet
};
