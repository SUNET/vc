// Vendored, unmodified, from @sirosfoundation/dc-api v0.7.0
// (npm package dist/dc-api-full.bundle.js).
//
// The polyfill AND the web-wallets registry in ONE module instance. The
// library's separate ./polyfill and ./web-wallets bundles cannot be combined
// by a consumer that vendors raw JS: each inlines its own copy of the wallet
// registry, so a wallet registered through one is invisible to the other's
// navigator.credentials.create() shim (sirosfoundation/dc-api#23). This
// entry point exists for exactly this use.
//
//   Library: https://github.com/sirosfoundation/dc-api
// src/polyfill.ts
var _wallets = [];
var _installed = false;
var _originalGet = null;
var _originalCreate = null;
var _originalUAP = null;
var _polyfillCreatedDC = false;
var _opts = {
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

// src/web-wallets.ts
var _enabled = false;
var _opts2 = {
  showSelector: true
};
function _validateWalletUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid wallet URL: ${url}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`Wallet URL must use https: scheme, got ${parsed.protocol}`);
  }
}
function enableWebWallets(options) {
  if (_enabled) return;
  if (typeof globalThis.WalletCompanion !== "undefined") {
    return;
  }
  _opts2 = { ..._opts2, ...options };
  const api = {
    register(wallet) {
      _validateWalletUrl(wallet.url);
      if (wallet.icon) _validateWalletUrl(wallet.icon);
      registerWallet(wallet);
    },
    unregister(walletId) {
      unregisterWallet(walletId);
    },
    list() {
      return getRegisteredWallets();
    },
    supportsProtocol(protocol) {
      return getRegisteredWallets().some((w) => w.protocols.includes(protocol));
    }
  };
  try {
    Object.defineProperty(globalThis, "DigitalWallets", {
      value: Object.freeze(api),
      writable: false,
      configurable: true
    });
  } catch {
    return;
  }
  _enabled = true;
}
function disableWebWallets() {
  if (!_enabled) return;
  try {
    delete globalThis.DigitalWallets;
  } catch {
  }
  _opts2 = { showSelector: true };
  _enabled = false;
}
function isWebWalletsEnabled() {
  return _enabled;
}
async function selectWallet(wallets, protocol) {
  if (_opts2.customSelector) {
    return _opts2.customSelector(wallets, protocol);
  }
  if (!_opts2.showSelector || wallets.length <= 1) {
    return wallets[0] ?? null;
  }
  return _showBuiltinSelector(wallets);
}
function _showBuiltinSelector(wallets) {
  return new Promise((resolve) => {
    let resolved = false;
    function finish(result) {
      if (resolved) return;
      resolved = true;
      dialog.remove();
      resolve(result);
    }
    const dialog = document.createElement("dialog");
    dialog.setAttribute("aria-label", "Select a wallet");
    dialog.style.cssText = `
			border: none; border-radius: 12px; padding: 24px;
			max-width: 360px; width: 90vw; box-shadow: 0 8px 32px rgba(0,0,0,0.2);
			font-family: system-ui, -apple-system, sans-serif;
		`;
    const title = document.createElement("h2");
    title.textContent = "Select a wallet";
    title.style.cssText = "margin: 0 0 16px; font-size: 18px;";
    dialog.appendChild(title);
    const list = document.createElement("div");
    list.style.cssText = "display: flex; flex-direction: column; gap: 8px;";
    for (const wallet of wallets) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.style.cssText = `
				display: flex; align-items: center; gap: 12px;
				padding: 12px 16px; border: 1px solid #ddd; border-radius: 8px;
				background: white; cursor: pointer; width: 100%; text-align: left;
				font-size: 15px; transition: background 0.15s;
			`;
      btn.onmouseenter = () => {
        btn.style.background = "#f5f5f5";
      };
      btn.onmouseleave = () => {
        btn.style.background = "white";
      };
      if (wallet.icon) {
        const img = document.createElement("img");
        img.src = wallet.icon;
        img.alt = "";
        img.width = 32;
        img.height = 32;
        img.style.cssText = "border-radius: 6px;";
        btn.appendChild(img);
      }
      const label = document.createElement("span");
      label.textContent = wallet.name;
      btn.appendChild(label);
      btn.onclick = () => finish(wallet);
      list.appendChild(btn);
    }
    dialog.appendChild(list);
    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.textContent = "Cancel";
    cancelBtn.style.cssText = `
			margin-top: 16px; padding: 8px 16px; border: none;
			background: transparent; cursor: pointer; color: #666;
			font-size: 14px; width: 100%;
		`;
    cancelBtn.onclick = () => finish(null);
    dialog.appendChild(cancelBtn);
    dialog.onclose = () => finish(null);
    document.body.appendChild(dialog);
    dialog.showModal();
  });
}
export {
  disableWebWallets,
  enableWebWallets,
  getRegisteredWallets,
  installPolyfill,
  isPolyfillInstalled,
  isWebWalletsEnabled,
  registerWallet,
  selectWallet,
  uninstallPolyfill,
  unregisterWallet
};
