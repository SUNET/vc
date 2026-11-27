# Embedding the presentation request

A relying party can render the presentation request on a page of its own
instead of sending people to the verifier's authorization page. The verifier
returns the request as data - the `openid4vp://` URI, a QR image, and where
to watch for the result - and the relying party decides how it looks.

There are two ways in, and which one fits depends on what the relying party
already is.

| | [OIDC](#oidc-relying-party) | [DCQL](#dcql-caller) |
|---|---|---|
| Entry point | `GET /authorize` with `Accept: application/json` | `POST /ui/interaction` |
| What it asks for | the scopes a registered client is configured for | a DCQL query in the request body |
| Client authentication | `client_id` and `redirect_uri` checked against a registered client | **none** - see [Security](#security) |
| Result arrives by | polling `GET /poll/{session_id}` | SSE on `GET /ui/notify?session_id=` |
| Ends with | an authorization code to exchange at `/token` | the presented claims in the session |

## OIDC relying party

An OIDC relying party drives the normal authorization-code flow, with one
difference: it asks `/authorize` for JSON rather than following the redirect
into the verifier's page.

```http
GET /authorize?response_type=code&client_id=rp&redirect_uri=https://rp.example.com/cb&scope=openid%20profile&state=xyz HTTP/1.1
Accept: application/json
```

```json
{
  "session_id": "0f1c…",
  "qr_code_data": "openid4vp://cb?client_id=…&request_uri=https%3A%2F%2Fverifier.example.com%2Fverification%2Frequest-object%2F0f1c…",
  "qr_code_image_url": "/qr/0f1c…",
  "deep_link_url": "openid4vp://cb?client_id=…&request_uri=…",
  "poll_url": "/poll/0f1c…",
  "wallet_links": [{"name": "…", "url": "…", "qr_code_image_url": "/qr/0f1c…?wallet=…"}],
  "title": "…", "primary_color": "…", "logo_url": "…"
}
```

Render `qr_code_data` as a QR code for the cross-device flow, and offer
`deep_link_url` as a link for someone already on their phone. If you would
rather not draw the QR yourself, point an `<img>` at `qr_code_image_url` -
it carries no cookie and needs none.

`qr_code_image_url` and `poll_url` are root-relative, as is
`wallet_links[].qr_code_image_url`. On a relying party's own page they would
resolve against *its* host, so join them to the verifier's base URL as the
page reaches it, keeping any mount prefix:

```js
const verifier = "https://rp.example.com/verify";   // or the verifier's own origin
const qr   = verifier + response.qr_code_image_url; // …/verify/qr/0f1c…
const poll = verifier + response.poll_url;          // …/verify/poll/0f1c…
```

`qr_code_data` and `deep_link_url` are absolute already - they are what the
wallet resolves, not the browser - and need no joining.

Then poll:

```http
GET /poll/0f1c… HTTP/1.1
```

```json
{"status": "awaiting_presentation"}
```

`status` is one of `pending`, `awaiting_presentation`, `code_issued`,
`token_issued`, `completed`, `expired`, `error`. When it reaches
`code_issued` the reply also carries `redirect_uri`: your own callback with
`code` and `state` already appended. Follow it and exchange the code at
`/token` exactly as you would have if the browser had been redirected there.

Anything that expresses no preference between HTML and JSON still gets the
page, so a browser visiting `/authorize` directly is unaffected. Only
`Accept` ranking `application/json` above `text/html` switches the response.

## DCQL caller

A caller that is not an OIDC client, and wants to name the credentials and
claims itself, posts a DCQL query:

```http
POST /ui/interaction HTTP/1.1
Content-Type: application/json

{"dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {…}, "claims": […]}]}}
```

```json
{
  "session_id": "9ab2…",
  "authorization_request": "openid4vp://cb?client_id=…&request_uri=…",
  "qr_code": "iVBORw0KGgoAAAANSUhEUg…",
  "dc_api_authorization_request": "…"
}
```

`qr_code` is a base64-encoded PNG with no data-URI prefix, so an `<img>` tag
needs one added:

```html
<img src="data:image/png;base64,{{ qr_code }}">
```

`dc_api_authorization_request` is present when the Digital Credentials API
is enabled, and is the request to hand to `navigator.credentials.get()`. It
is a different request from `authorization_request`, because `response_mode`
has to match the delivery channel.

**It only works when the calling page is served from `verifier.public_url`.**
The request's signed `expected_origins`, and the transcript the presentation
is checked against, are both derived from that configured value rather than
from the caller - accepting the caller's own word for its origin would be
the same as not checking it. A page on a different origin produces a
transcript the wallet did not build, and verification fails. Behind a
reverse proxy this holds as long as `public_url` is the proxied URL the page
is served from; for an embedding on a genuinely different origin, use the QR
code and the deep link, which carry no such binding.

Subscribe to the result rather than polling:

```js
new EventSource(`${verifier}/ui/notify?session_id=${sessionID}`);
```

`session_id` on the query string is what makes this work from another
origin; without it the endpoint falls back to the cookie session.

## Cross-origin configuration

List the relying party's origin, or the verifier answers no preflight:

```yaml
verifier:
  api_server:
    cors:
      allowed_origins: ["https://rp.example.com"]
```

That is all either flow needs. None of the endpoints above sits behind the
session cookie: `/authorize`, `/qr/{session_id}` and `/poll/{session_id}`
are registered outside the session middleware and address the authorization
context by its id, `POST /ui/interaction` sets the cookie but does not
require one, and `GET /ui/notify?session_id=` takes the session from the
query parameter, falling back to the cookie only when it is absent.

### When the cookie settings are needed

`verifier_user_session` backs the rest of `/ui/*` - `/ui/resume` and
`/ui/completion` resolve their session from the cookie - along with `op/par`
and the session-scoped `/verification/*` endpoints. An integration that
stays on the endpoints above never sends it, and should leave these keys
alone: widening a cookie that nothing in the flow reads exposes sessions to
cross-site requests and to sibling hosts for no gain.

For an integration that does reach a cookie-backed endpoint from another
site:

```yaml
verifier:
  api_server:
    trust_proxy_tls: true          # or api_server.tls.enable
    session_cookie:
      same_site: none              # lax (default) | strict | none
      domain: .example.com         # omit for a host-only cookie
```

- `same_site: none` is what lets the cookie survive a cross-site request. A
  browser stores it only when the cookie is also `Secure`, so the verifier
  refuses to start with `same_site: none` unless `tls.enable` or
  `trust_proxy_tls` is set - rather than serving a cookie every browser
  silently drops.
- `domain` scopes the cookie to a registrable domain and its subdomains, so
  one session reaches a verifier and a page on two hosts of the same site.
  Leave it out for a host-only cookie, which is the default: only the exact
  host that set it gets it back. Any host under a `domain` you set can read
  the session, so set it to a domain the deployment controls.

**Prefer same-origin.** Putting the verifier behind the relying party's own
reverse proxy - say `https://rp.example.com/verify/` - avoids all of this:
no CORS entry, no cookie widening, and the session cookie stays host-only.
Set `verifier.public_url` to the proxied URL so the `request_uri` the wallet
is handed resolves from outside.

## Security

**`/ui/interaction` authenticates no client.** `/authorize` checks
`client_id` against a registered client and `redirect_uri` against that
client's list; `/ui/interaction` checks neither, and will build a
presentation request from any DCQL query it is given. Exposing it to a
relying party's page exposes it to everyone who can reach that page, and
anyone who can reach it can mint presentation requests carrying this
verifier's identity.

Treat it as an endpoint to put behind the relying party's own
authentication, on a deployment dedicated to that relying party. It is not
suitable for a verifier shared between tenants, and it is why this flow is
not offered on a multi-tenant hosted deployment.

`/qr/{session_id}` and `/poll/{session_id}` take an unguessable session id
and return nothing about the holder - a QR image and a status - but they do
confirm that a session id exists.
