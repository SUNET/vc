# Cross-device flow: survive a page reload

Follow-up to PR #719 / issue #718. That PR fixed the same-device click race;
this plan covers the separate case where the user hits F5 (or a bfcache
restore triggers a reload) in the verifier UI while a cross-device wallet
scan is still in flight.

## Symptom

1. Browser tab loads `/`, JS calls `POST /ui/interaction`, gets `session_A`,
   renders QR bound to `state_A` and opens SSE keyed to `session_A`.
2. User scans QR on phone. The wallet starts talking to the verifier out of
   band.
3. User reloads the tab (F5, pull-to-refresh, back/forward that goes through
   the `pageshow persisted` handler in `presentation-definition.js`).
4. JS re-runs, calls `POST /ui/interaction` again. The endpoint mints
   `session_B`, overwrites the cookie, creates a fresh authorization
   context, and opens SSE keyed to `session_B`. New QR shown.
5. Wallet finishes and hits `POST /verification/direct_post` for `state_A`.
   `handlers_verification.go` looks up the auth context by state, finds
   `session_A`, and calls `c.notify.Submit(session_A, ...)`. Nothing is
   listening. The wallet gets 200 OK; the browser never redirects.

Same failure mode on a hard reload, on any browser that discards the
EventSource for the reloaded page, and on the deliberate reload that the
`pageshow persisted` handler forces after bfcache.

## Root causes

- `internal/verifier/httpserver/endpoints_ui.go` `endpointUIInteraction`
  unconditionally does `sessionID := uuid.NewString()` and
  `session.Set("session_id", sessionID)`. There is no branch that reuses an
  in-flight session.
- The SSE listener in the same file is keyed to whatever `session_id` the
  cookie currently holds. After step 4 above the cookie's id no longer
  matches the id the wallet is completing against.
- The client discards `presentationDefinition` on reload (module-scoped JS
  state), so there is no client-side memory of `session_A` either.
- `pageshow` handler in `internal/verifier/staticembed/presentation-definition.js`
  hard-reloads on bfcache restore, which turns a back/forward into the same
  broken path.

## Non-goals

- Do not try to survive the tab being closed. That is a separate
  wallet-hand-off problem (email/SMS resume link) and is out of scope.
- Do not touch the same-device flow. `WalletFollowsRedirect` returns
  `redirect_uri` from `direct_post`; SSE is already irrelevant on that path.
- Do not persist authorization contexts longer than they already live.
  Reuse existing TTLs.

## Design

> **Note (implementation update):** this plan originally positioned the
> shared gin cookie as the primary reuse channel. The shipped implementation
> deliberately does **not** treat the cookie as a reuse hint, because the
> cookie is per-origin and any sibling tab overwrites it; a fresh tab would
> otherwise inherit another tab's in-flight authorization context. Only the
> tab-scoped `session_id` in the request body (persisted in
> `sessionStorage` on the client) can trigger reuse. The sections below are
> kept for historical context; where they say "cookie reuse" or "cookie is
> the primary channel", read "body reuse" / "body is the primary channel".
> The SSE `?session_id=` query param in §4 is the sole mechanism that still
> uses the cookie, as a fallback when neither `sessionStorage` nor a
> query-string id is available.

Two mutually reinforcing changes: server reuses an existing session when the
request body carries a still-live `session_id` hint, and the client
remembers its session id across reloads so the hint survives reloads and
cross-tab cookie overwrites.

### 1. Server: reuse an in-flight session on `/ui/interaction`

Change `endpointUIInteraction` to prefer the cookie's `session_id` when all
of the following hold:

- The cookie carries a non-empty `session_id`.
- `cacheService.AuthContext.GetByID(ctx, sessionID)` returns a context.
- The context is *reusable*, meaning:
  - `authCtx.Forfeited` is false,
  - `authCtx.Token` is nil (no wallet has completed the flow),
  - `authCtx.Code` is empty (no OIDC code issued),
  - `authCtx.ExpiresAt == 0 || authCtx.ExpiresAt > time.Now().Unix()`,
  - the `RequestObject` for `authCtx.RequestObjectID` is still in
    `c.openid4vp.RequestObjectCache` (5-minute TTL; see
    `internal/verifier/apiv1/client.go` `RequestObjectTTL`).
- The `DCQLQuery` on the incoming request equals the one the existing
  context was created with. If the UI changed the query (user picked a
  different preset), we must not reuse the context — treat it as a new
  interaction.

When those hold, `UIInteraction` returns the *existing*
`AuthorizationRequest`, `QRCode`, `SessionID`, and (if applicable)
`DCAPIAuthorizationRequest`. When they do not, the current path runs: new
session id, new auth context, cookie overwritten.

Implementation notes:

- The reuse decision belongs in `apiv1.UIInteraction`, not the HTTP layer,
  so both the standalone verifier UI and the OIDC-OP path benefit. The HTTP
  layer keeps its "seed cookie session with `sessionID`" behaviour but
  *only overwrites the cookie* when the returned `SessionID` differs from
  the one it passed in.
- `UIInteractionRequest.SessionID` (already present, currently populated
  from the cookie) becomes the reuse hint. `UIInteraction` treats it as
  "reuse this id if you can, otherwise mint a fresh one and return that".
- Reuse must regenerate `QRCode` from the cached `AuthorizationRequest`
  string, not remint the request. That keeps `state`, `nonce`,
  `EphemeralEncryptionKeyID`, and the request_uri stable — exactly what the
  wallet is still holding.
- Add a metric/log line distinguishing "reuse" from "fresh" so we can see
  in production how often reload actually happens.

### 2. Client: persist `session_id` across reloads

Store `presentationDefinition.session_id` in `sessionStorage` right after
`sendDcqlQuery` succeeds. On page load, before the first `/ui/interaction`
POST, read it and include it in the body under a new `session_id` field
(the reuse hint above).

- `sessionStorage`, not `localStorage`: scoped to the tab, cleared on tab
  close. Matches the lifetime of an in-flight wallet flow.
- The server treats a client-supplied `session_id` exactly like a
  cookie-supplied one: reuse if reusable, ignore otherwise. The cookie
  remains the primary channel; the body is the fallback when the cookie is
  gone (or partitioned).
- On successful completion (SSE `redirect_uri` event) clear the key so a
  subsequent visit does not attempt to reuse a consumed session.
- Clear the key in `handleResetCancel` too.

### 3. bfcache handler: stop hard-reloading

`presentation-definition.js` `pageshow` listener currently does
`window.location.reload()` on `event.persisted`. That was defensive because
of stale in-memory state. With the session-reuse plumbing above, the safer
behaviour is:

- On bfcache restore, verify the SSE `EventSource` is still open. If not,
  reopen it against the same `session_id` from `sessionStorage`.
- Only fall back to `location.reload()` if the reuse hint is missing or if
  the `/ui/interaction` POST that follows returns a *different* session id
  than the stored one (server refused reuse — the auth context expired or
  was consumed).

This keeps back/forward navigation smooth in the common case and only
resets when the server tells us the flow is truly gone.

### 4. SSE: make the listener addressable by session id, not cookie

Today `endpointUINotify` reads `session_id` from the cookie. Accept it also
as a `?session_id=` query param (validated against the cookie when both are
present, matched exactly; the query param wins over the cookie so the
reloaded tab can subscribe to the id it remembered even if the cookie has
already been replaced by a concurrent tab in the same origin).

This is what makes the "concurrent tabs" edge case survive: tab A reloads
after tab B started a new `/ui/interaction`; A's cookie now points at B's
session, but A's `sessionStorage` still remembers `session_A`, so A's SSE
subscribes to `session_A` and receives the wallet's completion.

## Test plan

Add integration-style tests in
`internal/verifier/httpserver/endpoints_ui_test.go` (new file) that use the
existing memory cache backend:

1. `TestUIInteraction_ReuseCookieSession` — call twice with the same cookie
   and identical DCQL, assert same `SessionID`, same `authorization_request`,
   same `RequestObjectID` in cache.
2. `TestUIInteraction_ReuseBodySession` — call once, clear cookie, call
   again with the returned `session_id` in the body, assert reuse.
3. `TestUIInteraction_NoReuseAfterCompletion` — call once, mark the auth
   context as having a `Token`, call again, assert a new session id.
4. `TestUIInteraction_NoReuseAfterForfeit` — `Forfeited = true`, assert
   fresh session.
5. `TestUIInteraction_NoReuseAfterExpiry` — set `ExpiresAt` in the past,
   assert fresh session.
6. `TestUIInteraction_NoReuseOnDCQLChange` — same session hint, different
   DCQL, assert fresh session (and old context untouched).
7. `TestUINotify_QueryParamOverridesCookie` — SSE with `?session_id=X` and
   a cookie holding `Y` subscribes to `X`; `notify.Submit(X, ...)` reaches
   the client.
8. `TestReload_CrossDevice_EndToEnd` — the failure case in this document:
   create session_A, simulate reload with `sessionStorage` restore, submit
   `direct_post` for the original state, assert the reloaded SSE receives
   the `redirect_uri` event.

Plus a JS unit test if we grow one; today the JS is untested. Consider a
`vitest` harness under `internal/verifier/staticembed/` — out of scope for
this PR, but call it out.

## Rollout

- No config flag. In HA the cache spans nodes, so there is no failure mode
  a sysadmin would flip this off to avoid; a runtime toggle would only be
  another knob no one is going to touch. The reuse path is entered
  whenever a session_id hint arrives (cookie or body) and passes the
  reusability checks. Otherwise a fresh session is minted, exactly as
  today.
- No proto changes. No storage migration. The new `session_id` field on
  `UIInteractionReply` is already shipped in PR #719.
- A log line distinguishes "reused" from "fresh" so reload traffic is
  observable.

## Open questions

- Does the OIDC-OP-driven flow (which pre-seeds `session_id` in the
  request body from its own template) currently rely on `/ui/interaction`
  minting a fresh id? Check `internal/apigw` or wherever the OIDC-OP
  template is rendered before enabling reuse there.
- Should we prune the abandoned `session_A` context on `state_A` completion
  when the browser has moved on to `session_B`? Right now it just times out.
  Not urgent, but nice for cache pressure.
- Multi-window UX: if the same user has the same origin open in two tabs
  and reloads only one, both cookie and `sessionStorage` may point at
  different sessions. The query-param SSE override handles the SSE side.
  Confirm `handleWalletClick` picks its `session_id` from `sessionStorage`
  (not the reply cache) so its `session-preference` POST also targets the
  right one.

## Not part of this PR

- Wallet-side resume tokens, email hand-off, out-of-band callback URLs.
- Persistent server-side session storage. In-memory + Mongo cache TTLs are
  sufficient for the reload window we care about.
- Redesign of the `notify` package. `broadcast.Broadcaster` keyed by id
  is fine; we are only widening how the id is discovered.
