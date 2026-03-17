# Using the Verifier as an OIDC Login Provider

## What Is This?

The verifier can act as a standard OpenID Connect (OIDC) login provider. This means any application that supports "Login with OIDC" can use the verifier to authenticate users — except instead of passwords, users prove their identity by presenting verifiable credentials from a digital wallet.

From your application's point of view, the verifier looks and behaves like any other OIDC provider (similar to Google, Microsoft, or Keycloak). Your application redirects the user to the verifier, the user presents their credential via a wallet app, and your application receives identity information (name, email, birthdate, etc.) in a standard OIDC token.

### How It Works

1. Your application sends the user to the verifier's login page.
2. The verifier presents a way to connect to the user's wallet — a QR code on desktop, or a deep link / browser-mediated prompt on mobile (see [Wallet Interaction Methods](#wallet-interaction-methods) for details).
3. The user presents their credential from the wallet app.
4. The verifier checks the credential, then sends the user back to your application with a login token containing the verified identity information.

```text
┌────────────────┐       ┌────────────────┐       ┌────────────────┐
│                │       │                │       │                │
│  Your App      │       │   Verifier     │       │  User's Wallet │
│  (website /    │       │   (login       │       │  (mobile app)  │
│   service)     │       │    provider)   │       │                │
│                │       │                │       │                │
└───────┬────────┘       └───────┬────────┘       └───────┬────────┘
        │                        │                        │
        │  1. Redirect user      │                        │
        │   to verifier login    │                        │
        ├───────────────────────►│                        │
        │                        │                        │
        │                        │  2. Show QR code       │
        │                        │                        │
        │                        │  3. User scans QR      │
        │                        │◄───────────────────────┤
        │                        │                        │
        │                        │  4. Request credential  │
        │                        ├───────────────────────►│
        │                        │                        │
        │                        │  5. User presents      │
        │                        │     credential         │
        │                        │◄───────────────────────┤
        │                        │                        │
        │  6. Redirect back      │                        │
        │   with login token     │                        │
        │◄───────────────────────┤                        │
        │                        │                        │
        │  7. Your app gets      │                        │
        │   user's name,         │                        │
        │   email, etc.          │                        │
        │                        │                        │
```

---

## Before You Start

To connect your application to the verifier, you need to:

1. **Register your application** with the verifier (so it knows who you are).
2. **Configure your application** to use the verifier as its login provider.

There are two ways to register your application: adding it to the verifier's configuration file, or registering it at runtime via an API call. Both are described below.

You'll also need to know the **verifier's URL** (e.g., `https://verifier.sunet.se`). Ask your verifier administrator if you don't have this.

---

## Option A: Add Your Application to the Configuration File

This is the simplest approach. Ask the verifier administrator to add your application to `config.yaml`:

```yaml
verifier:
  oauth_server:
    clients:
      "my-app":                                       # This becomes your client ID
        type: "public"                                 # See note below
        redirect_uri: "https://my-app.sunet.se/callback"  # Where users return after login
        scopes:
          - "openid"
          - "profile"
          - "pid"
```

After editing, the verifier must be restarted for the changes to take effect.

**What you need to provide the administrator:**

| Information | Example | Description |
| ----------- | ------- | ----------- |
| A name for your app | `my-app` | Used as the client ID. Pick something short and descriptive. |
| Client type | `public` or `confidential` | Use `public` for browser-based apps (SPAs). Use `confidential` for server-side apps that can keep a secret. |
| Callback URL | `https://my-app.sunet.se/callback` | The URL in your app where users are sent after login. |
| Scopes | `openid`, `profile`, `pid` | What identity information you need (see [Available Scopes](#available-scopes) below). |

**When to use this method:**

- You have access to the verifier administrator.
- Your application's settings (callback URL, needed scopes) won't change often.
- You want the simplest possible setup.

**Limitations:**

- Only one callback URL per application.
- Any changes require editing the file and restarting the verifier.
- Only `public` clients can be registered this way (no client secret).

---

## Option B: Register Your Application via the API (Dynamic Registration)

If the verifier supports dynamic registration, your application can register itself by sending an API request. This is useful when you don't have access to the verifier's configuration file, or you need to register many applications.

### Registering

Send a POST request to the verifier's registration endpoint:

```bash
curl -X POST https://verifier.sunet.se/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://my-app.sunet.se/callback"],
    "client_name": "My Application",
    "scope": "openid profile pid",
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

The verifier responds with your credentials:

```json
{
  "client_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "client_secret": "dGhpcyBpcyBhIHNlY3VyZSBjbGllbnQgc2VjcmV0",
  "registration_access_token": "cmVnaXN0cmF0aW9uIGFjY2VzcyB0b2tlbg",
  "registration_client_uri": "https://verifier.sunet.se/register/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "redirect_uris": ["https://my-app.sunet.se/callback"],
  "client_name": "My Application",
  "scope": "openid profile pid",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

> **Save these values immediately.** The `client_secret` and `registration_access_token` are shown only once. If you lose them, you will need to register again.

**What each value means:**

| Value | What it is | What to do with it |
| ----- | ---------- | ------------------ |
| `client_id` | Your application's unique identifier. | Configure it in your OIDC library / application settings. |
| `client_secret` | A password for your application. | Store securely. Used when exchanging login codes for tokens. |
| `registration_access_token` | A management key for this registration. | Store securely. Needed only if you want to update or delete the registration later. |
| `registration_client_uri` | URL to manage your registration. | Use for later updates or deletion. |

### Registration Options

When registering, you can include these fields:

| Field | Required | What it does |
| ----- | -------- | ------------ |
| `redirect_uris` | **Yes** | Where users are sent after login. You can list multiple URLs. No URL fragments (`#`) allowed. |
| `client_name` | No | A human-readable name for your application. |
| `scope` | No | What identity information you need (space-separated). Defaults to `openid`. |
| `token_endpoint_auth_method` | No | How your app authenticates. Use `client_secret_basic` (default) or `client_secret_post` for server-side apps. Use `none` for browser-only apps. |
| `subject_type` | No | Use `pairwise` if you want each user to have a unique identifier specific to your app (recommended for privacy). Defaults to `public`. |
| `client_uri` | No | Your application's website URL (must be HTTPS). |
| `logo_uri` | No | URL to your logo (must be HTTPS). |
| `contacts` | No | Email addresses of people responsible for this app. |
| `policy_uri` | No | Link to your privacy policy (must be HTTPS). |
| `tos_uri` | No | Link to your terms of service (must be HTTPS). |

### Updating Your Registration

To change your registration (for example, to add a new callback URL or change your allowed scopes):

```bash
curl -X PUT https://verifier.sunet.se/register/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 \
  -H "Authorization: Bearer cmVnaXN0cmF0aW9uIGFjY2VzcyB0b2tlbg" \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": [
      "https://my-app.sunet.se/callback",
      "https://my-app.sunet.se/new-callback"
    ],
    "scope": "openid profile pid ehic"
  }'
```

You only need to include the fields you want to change — everything else stays the same.

### Viewing Your Registration

```bash
curl https://verifier.sunet.se/register/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 \
  -H "Authorization: Bearer cmVnaXN0cmF0aW9uIGFjY2VzcyB0b2tlbg"
```

### Deleting Your Registration

```bash
curl -X DELETE https://verifier.sunet.se/register/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 \
  -H "Authorization: Bearer cmVnaXN0cmF0aW9uIGFjY2VzcyB0b2tlbg"
```

---

## Connecting Your Application

Once your application is registered, you need to configure it to use the verifier as its OIDC provider. Most web frameworks and OIDC libraries handle this automatically — you just need to provide a few settings.

### Settings Your Application Needs

| Setting | Value | Where to find it |
| ------- | ----- | ----------------- |
| Discovery URL | `https://verifier.sunet.se/.well-known/openid-configuration` | The verifier's base URL + `/.well-known/openid-configuration` |
| Client ID | `my-app` or `a1b2c3...` | From the config file (Option A) or the registration response (Option B) |
| Client secret | _(only for confidential clients)_ | From the registration response (Option B) |
| Callback URL | `https://my-app.sunet.se/callback` | The URL you registered |
| Scopes | `openid profile pid` | What you registered for |

Most OIDC libraries can auto-discover all the endpoints from the Discovery URL. If your library requires individual endpoint URLs, fetch the discovery document:

```bash
curl https://verifier.sunet.se/.well-known/openid-configuration
```

This returns all the URLs you need (authorization endpoint, token endpoint, etc.).

### How the Login Flow Works

This is what happens when a user clicks "Log in" in your application:

**1. Your app redirects the user to the verifier.**

Your OIDC library handles this automatically. The redirect URL looks like:

```text
https://verifier.sunet.se/authorize
  ?response_type=code
  &client_id=my-app
  &redirect_uri=https://my-app.sunet.se/callback
  &scope=openid profile pid
  &state=<random-value>
  &nonce=<random-value>
  &code_challenge=<PKCE-value>
  &code_challenge_method=S256
```

**2. The user sees a login page with a QR code.**

The verifier shows a QR code that the user scans with their wallet app (or a deep link on mobile). The QR code tells the wallet what credentials are needed based on the requested scopes.

**3. The user presents their credential in the wallet.**

The wallet shows the user which information will be shared. The user confirms, and the wallet sends the credential to the verifier.

**4. The verifier sends the user back to your app.**

After verifying the credential, the verifier redirects to your callback URL with an authorization code:

```text
https://my-app.sunet.se/callback?code=abc123&state=<same-random-value>
```

**5. Your app exchanges the code for tokens.**

Your OIDC library does this automatically. It sends the authorization code to the verifier's token endpoint and receives:

- An **ID token** — a signed token containing the user's verified identity information (name, birthdate, etc.).
- An **access token** — used to fetch additional user information if needed.

**6. Your app reads the user's identity from the token.**

The ID token contains claims like:

```json
{
  "sub": "unique-user-identifier",
  "given_name": "Jane",
  "family_name": "Doe",
  "birthdate": "1990-01-15",
  "email": "jane.doe@sunet.se"
}
```

The exact claims depend on the scopes you requested and what's in the user's credential.

**7. (Optional) Your app calls the UserInfo endpoint.**

If you need additional claims, use the access token:

```bash
curl https://verifier.sunet.se/userinfo \
  -H "Authorization: Bearer <access_token>"
```

---

## Available Scopes

Scopes determine what information your application receives about the user. Each scope maps to a type of verifiable credential.

| Scope | What it provides | Credential type |
| ----- | ---------------- | --------------- |
| `openid` | **Required.** Enables the OIDC login flow. | _(standard OIDC)_ |
| `profile` | Basic identity: name, birthdate | PID (Person Identification Data) |
| `email` | Email address | _(standard OIDC)_ |
| `pid` | Full PID attributes: name, birthdate, nationality, etc. | PID |
| `ehic` | European Health Insurance Card data | EHIC |
| `pda1` | Portable Document A1 (social security) | PDA1 |
| `elm` | European Learning Model credential | ELM |
| `diploma` | Diploma / degree information | Diploma |
| `eduid` | eduID identity attributes | eduID |

Always include `openid`. Add other scopes based on what information you need. For example:

- **Basic login:** `openid profile` — gives you the user's name and birthdate.
- **Identity verification:** `openid pid` — gives you full PID attributes.
- **Health insurance check:** `openid ehic` — gives you EHIC data.

> **Note:** Users can only provide scopes for credentials they actually have in their wallet. If a user doesn't have an EHIC credential, they won't be able to complete a login that requires the `ehic` scope.

---

## Complete Examples

### Example 1: Server-Side Web Application (Go)

This example uses a Go web application with the `coreos/go-oidc` and `golang.org/x/oauth2` libraries.

**Install the dependencies:**

```bash
go get github.com/coreos/go-oidc/v3/oidc
go get golang.org/x/oauth2
```

**Application code:**

```go
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	ctx := context.Background()

	// Discover the verifier's OIDC configuration
	provider, err := oidc.NewProvider(ctx, "https://verifier.sunet.se")
	if err != nil {
		log.Fatalf("Failed to discover provider: %v", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     "my-app",
		ClientSecret: "my-secret", // Omit for public clients
		RedirectURL:  "https://my-app.sunet.se/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "pid"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: "my-app"})

	// Login handler — redirects the user to the verifier
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		state, _ := randomString(32)
		nonce, _ := randomString(32)
		codeVerifier, _ := randomString(64)

		// Store state, nonce, and PKCE verifier in a cookie or session
		http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: state, HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "oauth_nonce", Value: nonce, HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "pkce_verifier", Value: codeVerifier, HttpOnly: true})

		codeChallenge := sha256Base64url(codeVerifier)

		url := oauth2Config.AuthCodeURL(state,
			oidc.Nonce(nonce),
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
		http.Redirect(w, r, url, http.StatusFound)
	})

	// Callback handler — exchanges the code for tokens
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Verify state
		stateCookie, _ := r.Cookie("oauth_state")
		if stateCookie == nil || r.URL.Query().Get("state") != stateCookie.Value {
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}

		// Get PKCE verifier from cookie
		verifierCookie, _ := r.Cookie("pkce_verifier")
		if verifierCookie == nil {
			http.Error(w, "Missing PKCE verifier", http.StatusBadRequest)
			return
		}

		// Exchange authorization code for tokens
		token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"),
			oauth2.SetAuthURLParam("code_verifier", verifierCookie.Value),
		)
		if err != nil {
			http.Error(w, "Token exchange failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Verify the ID token
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No ID token in response", http.StatusInternalServerError)
			return
		}

		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "ID token verification failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Verify nonce
		nonceCookie, _ := r.Cookie("oauth_nonce")
		if nonceCookie == nil || idToken.Nonce != nonceCookie.Value {
			http.Error(w, "Nonce mismatch", http.StatusBadRequest)
			return
		}

		// Extract user claims
		var claims struct {
			GivenName  string `json:"given_name"`
			FamilyName string `json:"family_name"`
			Birthdate  string `json:"birthdate"`
			Email      string `json:"email"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Hello, %s %s!", claims.GivenName, claims.FamilyName)
	})

	// Home page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="/login">Log in with your wallet</a>`)
	})

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}

func sha256Base64url(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
```

### Example 2: Browser Application (JavaScript SPA)

This example uses a single-page application with no backend. Because there's no server to keep a secret, this uses a **public client** with PKCE for security.

**Register as a public client** (in config or via the API with `"token_endpoint_auth_method": "none"`).

```javascript
// --- Login button clicked ---

// Generate security values
const codeVerifier = generateRandomString(64);
const codeChallenge = await sha256Base64url(codeVerifier);
const state = generateRandomString(32);
const nonce = generateRandomString(32);

// Remember these for the callback
sessionStorage.setItem('pkce_verifier', codeVerifier);
sessionStorage.setItem('oauth_state', state);
sessionStorage.setItem('oauth_nonce', nonce);

// Redirect to verifier
const params = new URLSearchParams({
  response_type: 'code',
  client_id: 'my-spa',
  redirect_uri: 'https://my-spa.sunet.se/callback',
  scope: 'openid profile pid',
  state: state,
  nonce: nonce,
  code_challenge: codeChallenge,
  code_challenge_method: 'S256'
});

window.location.href =
  `https://verifier.sunet.se/authorize?${params}`;
```

```javascript
// --- On the callback page ---

const params = new URLSearchParams(window.location.search);

// Verify the state to prevent tampering
if (params.get('state') !== sessionStorage.getItem('oauth_state')) {
  alert('Login failed: state mismatch');
  throw new Error('State mismatch');
}

// Exchange the code for tokens
const response = await fetch('https://verifier.sunet.se/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.get('code'),
    redirect_uri: 'https://my-spa.sunet.se/callback',
    client_id: 'my-spa',
    code_verifier: sessionStorage.getItem('pkce_verifier')
  })
});

const tokens = await response.json();

// The ID token contains the user's identity
const idToken = parseJwt(tokens.id_token);
console.log(`Welcome, ${idToken.given_name} ${idToken.family_name}`);
```

### Example 3: Backend Service (curl)

This example walks through the complete flow using curl, useful for testing or scripting.

**Step 1 — Register (if using dynamic registration):**

```bash
curl -s -X POST https://verifier.sunet.se/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://my-service.sunet.se/callback"],
    "client_name": "My Service",
    "scope": "openid profile pid"
  }' | jq .

# Save the client_id and client_secret from the response
```

**Step 2 — Open the authorization URL in a browser:**

```text
https://verifier.sunet.se/authorize
  ?response_type=code
  &client_id=<your-client-id>
  &redirect_uri=https://my-service.sunet.se/callback
  &scope=openid+profile+pid
  &state=test123
  &nonce=nonce456
```

The user scans the QR code with their wallet. After presenting their credential, the browser redirects to your callback URL with a `code` parameter.

**Step 3 — Exchange the code:**

```bash
curl -s -X POST https://verifier.sunet.se/token \
  -u "<client_id>:<client_secret>" \
  -d "grant_type=authorization_code" \
  -d "code=<code-from-callback>" \
  -d "redirect_uri=https://my-service.sunet.se/callback" \
  | jq .
```

**Step 4 — Get user info:**

```bash
curl -s https://verifier.sunet.se/userinfo \
  -H "Authorization: Bearer <access_token>" \
  | jq .
```

---

## Choosing Between Pre-configured and Dynamic Registration

| | Pre-configured (config file) | Dynamic registration (API) |
| - | ---------------------------- | -------------------------- |
| **Best for** | Your own apps, fixed integrations | Third-party apps, self-service onboarding |
| **How to set up** | Admin edits a config file and restarts | App sends an API request at any time |
| **Callback URLs** | One per app | Multiple per app |
| **Client secret** | Not available (public clients only) | Automatically generated |
| **Can update later** | Edit file + restart | API call (no restart needed) |
| **Needs a database** | No | Yes (MongoDB) |

**Recommendation:** Use pre-configured registration when you have a small, fixed number of apps. Use dynamic registration when you need flexibility or self-service.

---

## Understanding Public vs. Confidential Clients

When registering your app, you need to decide whether it's a **public** or **confidential** client:

**Public clients** are applications that cannot keep a secret — typically browser-based single-page applications (SPAs) or mobile apps where the code is visible to the user. Public clients:

- Don't have a client secret.
- Must use PKCE (an extra security step that most OIDC libraries handle automatically).
- Set `type: "public"` in config, or `"token_endpoint_auth_method": "none"` in dynamic registration.

**Confidential clients** are server-side applications that can securely store a secret. Confidential clients:

- Have a client secret used to authenticate when exchanging codes for tokens.
- Should still use PKCE as an extra layer of security.
- Set `type: "confidential"` in config, or `"token_endpoint_auth_method": "client_secret_basic"` (or `"client_secret_post"`) in dynamic registration.

If you're not sure, choose **confidential** for server-side apps and **public** for everything running in a browser.

---

## What the User Sees

When a user is sent to the verifier's authorization page, the experience adapts to their device:

1. **On desktop:** A QR code is displayed for the user to scan with the wallet app on their **phone** (cross-device flow).
2. **On mobile:** A deep link button opens the wallet app directly on the **same device**, or — if the W3C Digital Credentials API is enabled and supported — the browser itself prompts the user to present a credential without switching apps.

### Wallet Interaction Methods

The authorization page automatically adapts to the user's device. The method used depends on whether the user is on a desktop or mobile device, their browser capabilities, and the verifier's configuration.

#### Desktop (user browses on a computer)

On a desktop computer the wallet app lives on the user's phone, so the page must bridge the two devices:

| Method | When shown | How it works |
| --- | --- | --- |
| **QR Code** (`openid4vp://`) | Always shown by default | The page displays a QR code encoding an `openid4vp://` URI. The user scans it with a native wallet app on their **phone**. This is the standard **cross-device** flow (desktop browser ↔ mobile wallet). |
| **Web wallet links** | When `supported_wallets` is configured | Clickable HTTPS links to known web wallets that open in the **desktop browser** itself. Each link also has a **QR code button** — clicking it reveals a QR code that, when scanned from a phone, opens the web wallet on the phone instead. This enables **cross-device** flow with web wallets (desktop browser ↔ mobile web wallet). |

> On desktop, the "Open in Wallet" deep link is hidden because there is typically no native wallet app installed on the computer.

#### Mobile (user browses on a phone or tablet)

On a mobile device the wallet app is on the **same device** as the browser, so the page can open it directly:

| Method | When shown | How it works |
| --- | --- | --- |
| **"Open in Wallet" deep link** | Automatically shown on mobile | A tappable `openid4vp://` link that launches the user's installed native wallet app directly. This is the primary **same-device** flow (mobile browser → mobile wallet app). |
| **W3C Digital Credentials API** | `digital_credentials.enable: true` in config AND the browser supports it (Chrome 128+ on Android) | The browser itself mediates wallet selection via `navigator.credentials.get()` — no QR code or app-switch needed. This is a **same-device, same-browser** flow where the credential is presented entirely within the browser's built-in wallet UI. |
| **QR Code** (`openid4vp://`) | Shown as a fallback | Still available on mobile, but typically less useful since the user cannot easily scan a QR code displayed on the same screen. Useful if the credential is in a wallet on a **second** device. |
| **Web wallet links** | When `supported_wallets` is configured | Same as on desktop — clickable HTTPS links to known web wallets, opening in the mobile browser. Each also has an optional QR code for use on a second device. |

#### How the page decides what to show

```text
User opens authorization page
│
├─ Desktop browser
│   ├─ Show QR code (primary — opens native wallet on phone)
│   ├─ Show web wallet links with QR toggle (if configured)
│   │   ├─ Click link → opens web wallet in desktop browser (same-device)
│   │   └─ Click QR → shows QR code → scan opens web wallet on phone (cross-device)
│   └─ Show "Present from Browser" button (if DC API enabled + supported)
│
└─ Mobile browser
    ├─ Show "Open in Wallet" deep link (primary)
    ├─ Show web wallet links with QR toggle (if configured)
    ├─ Show "Present from Browser" button (if DC API enabled + supported)
    └─ Show QR code (as fallback)
```

#### Configuration example

```yaml
verifier:
  # Web wallet links shown on the authorization page (desktop & mobile)
  supported_wallets:
    "SUNET Wallet": "https://wallet.sunet.se/cb"
    "Test Wallet":  "https://test-wallet.example.com/authorize"

  # W3C Digital Credentials API — browser-mediated wallet selection (mobile only today)
  digital_credentials:
    enable: true
    allow_qr_fallback: true
```

All methods result in the same outcome: the wallet presents a credential, the verifier validates it, the session completes, and the user is redirected back to the relying party application. The authorization page polls for completion regardless of which method was used.

The wallet app shows the user:

- Which application is requesting their information.
- Exactly which attributes will be shared (name, birthdate, etc.).
- A confirmation button to approve or deny.

Once the user confirms, they are automatically redirected back to your application and are logged in.

---

## Troubleshooting

### "Client not found" error

- Double-check the `client_id` in your application settings.
- For pre-configured clients: make sure the client is listed in `config.yaml` under `verifier.oauth_server.clients` and the verifier has been restarted.
- For dynamically registered clients: make sure the registration was successful and you're using the correct `client_id` from the registration response.

### "Invalid redirect URI" error

- The callback URL in the login request must **exactly match** a registered URL — including trailing slashes and query parameters.
- Check for typos, http vs. https, and missing or extra path segments.

### "Invalid scope" error

- Your application is requesting a scope it wasn't registered for.
- Make sure the scopes in your login request are a subset of the scopes you registered with.
- Always include `openid` as a scope.

### User is stuck on the QR code page

- The user's wallet app might not be installed or compatible.
- The QR code / session expires after a few minutes — refresh the page to get a new one.
- Check that the verifier's URL is reachable from both the user's browser and their wallet app.

### "Invalid grant" or PKCE error when exchanging the code

- The authorization code can only be used once. If you retry, you'll get this error.
- For PKCE: make sure the `code_verifier` sent to the token endpoint matches the `code_challenge` sent during the authorize step. Most OIDC libraries handle this automatically.
- The code expires after a few minutes (default: 5 minutes). Make sure the exchange happens promptly.

### Lost the registration access token

The registration access token is shown only once when you first register. If you lose it, you can't update or delete the registration via the API. Ask the verifier administrator to remove the client from the database, then register again.

### Too many requests (rate limit)

The registration endpoint is limited to a few requests per minute per IP address. If you hit this limit, wait a minute and try again.

---

## Security Tips

- **Always use HTTPS** for your callback URLs in production.
- **Always use PKCE** (`code_challenge_method: S256`). Most modern OIDC libraries enable this by default.
- **Store client secrets securely** — don't commit them to source control or expose them in browser-side code.
- **Validate the `state` parameter** on the callback to prevent cross-site request forgery.
- **Validate the ID token** — check the signature, issuer, audience, expiration, and nonce. Most OIDC libraries do this automatically.
- **Use pairwise subject identifiers** (`subject_type: "pairwise"`) if you don't need to correlate users across different applications. This improves user privacy.
- **Change the `subject_salt`** from its default value in production deployments.
