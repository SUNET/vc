# Pre-authorized offers for a login-gated credential

`POST /api/v1/datastore/preauth_offer` mints a pre-authorized credential
offer for a document already in the datastore. A wallet redeems it without
the user authenticating to this issuer at all — the offer *is* the
authorization.

That is safe for a credential whose scope has no other way to be issued.
It is not automatically safe for one an operator deliberately put behind a
login, which is what this page is about.

## The two questions `auth_provider` used to answer at once

`data_sources.datastore.scopes.<scope>.auth_provider` answers **how a user
authenticates when they start the flow themselves** — `openid4vp`, `saml`,
`oidc`. It had a fourth value, `preauth`, which answered a different
question: **may the issuer hand out an offer for this?**

Those are different dimensions. Pre-authorized is an OAuth *grant type*,
not an identity provider. Because one scope has exactly one
`auth_provider`, a credential that needed both — login-gated for users,
offerable by an operator — had to be configured twice, as `<type>` and
`<type>_offer`.

A scope is also a `credential_configuration_id`, so each twin appeared
twice in everything that lists credentials: the issuer's
`credential_configurations_supported`, the verifier's credential picker,
and every wallet's "add credential" list. Twelve types became
twenty-six entries.

## `allow_preauth_offer`

```yaml
apigw:
  data_sources:
    datastore:
      scopes:
        diploma:
          auth_provider: oidc        # unchanged: how a user logs in
          allow_preauth_offer: true  # and an operator may also mint an offer
```

The scope keeps its `auth_provider`. A wallet that starts the flow itself
authenticates exactly as it did, and the offer names the **base**
`credential_configuration_id` — `diploma`, not `diploma_offer`.

Nothing else changes. In particular the rejection of a wallet-initiated
PAR/authorize for a *real* `preauth` scope is untouched: that keys on
`auth_provider` and the flag never reaches it.

## It is refused at startup when it would be a login bypass

The flag removes the only configuration-level gate on an endpoint that
mints a credential the scope otherwise gates behind a login. That is
acceptable only where an authenticated principal actually reaches the
endpoint, and two configurations leave none:

**Neither Bearer mode configured.** With neither `api_auth.jwks` nor
`api_auth.oidc` enabled, the API-auth middleware is a pass-through.

```
apigw.data_sources.datastore.scopes sets allow_preauth_offer on login-gated
diploma but apigw.api_server.api_auth configures neither jwks nor oidc: …
anyone who can reach the port may call it
```

**The admin UI with OIDC off.** `/ui/login` grants a session with
`admin_subject` `anonymous` to anybody who asks, and `SessionOrAPIAuth`
accepts a session *instead of* falling through to the Bearer middleware —
so a JWKS configuration says nothing about this path.

```
apigw.data_sources.datastore.scopes sets allow_preauth_offer on login-gated
diploma with apigw.admin_ui_enable true and apigw.api_server.api_auth.oidc
disabled: … Configure oidc, or turn the admin UI off
```

Refused at startup rather than in the handler because the handler has no
better answer available: there is no authenticated principal to require,
so the only honest check is on the configuration that left none. This
mirrors the guard on `interactive_authorization`, for the same reason.

A scope whose `auth_provider` **is** `preauth` is not covered by either
refusal. Nothing is bypassed by minting an offer for a credential that has
no other way to be issued, and that is what the endpoint always did.

## Migrating off the twins

1. On the base scope, set `allow_preauth_offer: true`.
2. Move whatever mints offers from `<type>_offer` to `<type>`. The offer's
   `credential_configuration_ids` changes with it.
3. Delete the `<type>_offer` scope, its `credential_metadata` entry, and
   its issuer credential configuration.

Do them in that order. Step 3 before step 2 leaves offers naming a
configuration id the issuer no longer publishes, and the wallet resolves
that id against `credential_configurations_supported` — so the offer
becomes unredeemable rather than merely wrong.

For the same reason, **do not try to hide a twin by removing it from the
issuer metadata while offers still name it.** That map is a resolution
table, not a display list; OpenID4VCI has no hidden-configuration concept.
Until a twin's offers have moved, the entry has to stay published.
