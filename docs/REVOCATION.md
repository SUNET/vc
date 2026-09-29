# Credential revocation

vc implements revocation with the IETF Token Status List
(`draft-ietf-oauth-status-list`). A credential carries a reference to one
bit-range entry in a published status list; a verifier fetches that list,
reads the entry, and decides. Nothing about a credential changes when it is
revoked — the list does.

This document covers what is implemented, the wire format vc writes and
reads, how status list signers are trusted, and what is deliberately not
done yet.

## Two backends

| | `registry` | `external` |
| --- | --- | --- |
| Who publishes the list | vc's own registry service | a `draft-ietf-oauth-status-list` service, e.g. siros-status-service |
| Configured under | `apigw.registry_client` | `issuer.status_service` |
| Sharding | sections (`Section` is meaningful) | none; always section 0 |
| Required | no | no |

Both may be configured at once; each allocated entry records which backend
owns it, so a deployment can migrate without rewriting what it already
issued. Neither is required: with both absent, credentials are issued with
no status reference and revocation is simply not available.

The local registry being optional is why an allocated entry is identified by
its **URI**, not by its section, and why `Backend` — not the shape of the
URI — is what says who owns it.

## Issuance

The OpenID4VCI path (`PAR` → token → `/credential`) allocates one status
list entry per issued credential, embeds the reference in the credential,
and records `(status_list_uri, idx) → (identifier, authentic source, scope,
backend)` in the apigw's own store.

That recording is **required**, not best-effort: the entry is consumed
either way, and a credential whose entry was not recorded can never be
revoked. A failed recording fails the issuance and releases the allocation —
the wallet gets no credential and the slot goes back, which is recoverable.
The registry is written to as well when one is configured, because its admin
GUI reads from there, but only then and only best-effort.

Where the reference lives, per format:

| Format | Location | Read by the verifier |
| --- | --- | --- |
| SD-JWT VC | `status.status_list` claim | yes |
| mdoc | `status` in the MSO (draft Section 6.3) | yes |
| ZK mdoc | — | **refused**, see below |
| JWP (BBS) | the issuer protected header | not yet |
| W3C VC 2.0 | `credentialStatus` with `TokenStatusListEntry` | not yet — and off by default, see below |

A JWP carries its status in the issuer header rather than in a claim
deliberately: a claim would be one of the signed messages and so selectively
disclosable, and a revocation status a holder can decline to reveal is not
revocation. The verifier's status extraction reads claims, so it does not
find it there yet.

### ZK mdoc presentations are refused, not passed

A ZK mdoc presentation proves statements about claims without revealing the
document, so the verifier never sees an MSO and there is no status to read.
Letting it fall through to the generic claims check would find no status and
read that as "not revocable", which lets a revoked credential verify —
`formatCanCarryStatus` refuses the format instead.

### Limitation: OpenID4VCI only

Only the OpenID4VCI issuance path allocates and records status entries. The
OIDC-RP flow (`internal/apigw/apiv1/handlers_oidcrp.go`) calls `MakeSDJWT`
directly and issues credentials that carry no status reference and cannot be
revoked. Wiring it in means threading an allocation and a release through
that flow and deciding what identifier its entries are recorded under — the
OIDC-RP subject is not the authentic-source person id issuance uses. That is
its own change.

### Limitation: W3C VC 2.0 status is off by default

`issuer.vc20_status_enable` defaults to false. Two things are not yet true,
and both are visible to third parties rather than to us:

- the JSON-LD context defining `TokenStatusListEntry` lives under an RFC 2606
  `.invalid` namespace, which nobody else can dereference. vc resolves it
  from its embedded bundle, so our own stack works and no one else's does;
- nothing verifies it. W3C VC verification arrives separately, so a status
  emitted today is a reference no verifier fetches.

Issuance is implemented and tested, so flipping the flag is the whole change
once the namespace is chosen and verification lands. Defaulting it on would
mint credentials that look revocable and are not, which is worse than
minting none — the reference invites reliance on it.

## Revoking

`POST /api/v1/credential/revoke`, on the authenticated `api/v1` group
(`SessionOrAPIAuth` + CSRF). Revoking somebody else's credential is exactly
as damaging as issuing one.

The endpoint is **not registered at all** unless the deployment can
authorize it — `api_auth` must authenticate (jwks or oidc) and SPOCP rules
must exist. Both cases log a warning naming the missing configuration.
Authentication is not authorization: without rules, every authenticated
caller is unconstrained and could revoke any subject's credentials by
naming the identifier, which is their own input and establishes nothing.

Authorization is asked **per entry**, as one `(authentic_source, scope)`
pair, carrying this endpoint's method and path. Not as two membership
lists: flattening grants of `(SUNET, pid)` and `(OTHER, ehic)` into an
allowed-sources list and an allowed-scopes list authorizes their Cartesian
product, so `(SUNET, ehic)` would pass although it was never granted. And
not from a generic "is authenticated" check: a rule authorizing some other
`api/v1` path must not authorize revocation.

Entries the caller may not act on are skipped, not named — the response
does not tell a caller which credentials exist outside their grants. A
request that ends up acting on nothing is an error, not an empty success.

## Verification

`verifier.revocation`:

| Key | Meaning |
| --- | --- |
| `enabled` | turn the check on |
| `cache_ttl` | seconds to cache a fetched status list token |
| `fail_open` | what an unreachable or unparseable list means; default **true** |
| `skip_scopes` | scopes exempt from checking (ARF 3.0 §6.6.3.7 short-lived credentials) |
| `status_list_issuer` | identity to resolve a key under when the token carries no `iss` |
| `status_list_key_file` | PEM public key (or certificate) that signs status list tokens |

`fail_open: true` means a failure to check is tolerated and a **revoked
credential is accepted**. That is the default, so anything that makes
verification fail silently — an unreachable list, an unresolvable key — is a
security-relevant misconfiguration rather than a nuisance.

`status_list_issuer` alone is not always enough. It gives the
discovery-based resolver an identity to look for a JWKS under, and a status
service's status-list signing key need not be published there at all.
siros-status-service is one such case: its AS JWKS exists for access-token
verification while the status-list key is separate with no JWKS endpoint, so
discovery finds nothing and every external list fails to verify.
`status_list_key_file` **pins** the key — it is used for every token, with
or without an `iss`, because naming a key is a statement about which key
signs these lists.

Configure one or the other, or tokens without an `iss` claim are refused.

### What is checked before a status is believed

- `typ` — `statuslist+jwt` for a JWT, COSE protected header 16 for a CWT.
  Without this, any JWT or COSE_Sign1 signed by the same trusted key is
  accepted as a status list if its claims happen to be shaped alike.
- `sub` equals the URI the token was fetched from (Section 8.3). Checked
  **before** anything in the token is trusted, so a list cannot answer for
  a URI it was not served from.
- `exp`, explicitly, on both paths.
- the signature, against a key resolved as described below.

## Trusting the signer

A status list decides whether a credential is still valid, so "may this
party say that" is the same trust question asked of a credential's issuer
and is answered the same way — through go-trust, not by whoever happened to
serve the bytes.

`JWTTrustVerifier.VerifyStatusListToken` takes key material from the token's
**own header** (`x5c`, `jwk`, DID, or `kid` + JWKS discovery — the same
paths every other JWT here uses), verifies the signature with it, and then
evaluates the signer. The key the signature verified with is what goes to
the evaluator; re-resolving could return a different key from a rotating
resolver.

The subject is the token's `iss` when it has one, and otherwise the
**origin** of the list URI — Section 5.1's required claims are `sub`, `iat`
and `status_list`, so `iss` may be absent, and a policy still has to name
something.

Two evaluations are made, in order:

1. **`status-list-signer`**. Being trusted to issue credentials is not the
   same as being trusted to publish their revocation status. With an
   external status service the two are different parties signing with
   different keys, and judging the status service as a credential issuer
   would deny every legitimate one.
2. **`credential-issuer`**, only if the first did not produce a trusted
   decision. This is the common case — the credential issuer signing the
   status lists for its own credentials. That party is already named as an
   issuer, and a deployment should not have to name it a second time under
   a different action just to keep revocation working.

go-wallet-backend makes the same two calls in the same order, so one policy
set covers both ends of the exchange.

**Deployment note:** go-trust falls back to its DEFAULT policy for an
unknown action name, so a deployment defining neither action judges status
list signers by whatever the default says rather than failing loudly.

### Limitation: the CWT path is not trust-evaluated

`JWTTrustVerifier` works on JWTs. A status list served as a CWT still needs
a configured key resolver, and says so rather than failing later — it does
not go through the PDP. A deployment consuming CWT status lists is trusting
its key resolver, not its trust framework.

## CWT wire format

vc's CWT output diverged from the draft in four places at once, and each
divergence collided with something else the draft defines — a conforming
reader did not merely fail to understand vc's output, it misread it. All
four are now aligned:

| | vc wrote | draft |
| --- | --- | --- |
| `status_list` claim | 65534 | **65533** |
| `ttl` claim | 65535 | **65534** |
| StatusList members | integer labels 1/2/3 | **text** `bits` / `lst` / `aggregation_uri` |
| COSE header 16 | `statuslist+cwt` | **`application/statuslist+cwt`** |

65534 is the draft's `ttl`, so a conforming reader looking for a ttl found a
status_list map there; 65535 is the draft's `status` claim for a COSE
Referenced Token, so vc's ttl sat on a registered claim of a different type.
The member keys are text in the CDDL and in the draft's own annotated hex
(`a2 64 62697473 01 63 6c7374 …` — map(2), `"bits"`, `"lst"`).

**What vc writes is the draft's spelling. What vc reads is either.** The old
claim label, the old member labels and the bare subtype are all still
accepted, so a list published by an older vc verifies until it is next
regenerated — status lists are regenerated on a TTL, so the window is short.

The old status_list label is the new ttl label, so the fallback tells them
apart by type: a `ttl` is an unsigned integer, a `status_list` is a map.
Anything at 65534 that is not a map is a ttl, and a token carrying one but
no status_list is reported as missing a status_list rather than read as a
malformed one.

go-wallet-backend reads and writes the integer member labels today, which is
why vc reads them; it needs the matching text-key read before its own
publication changes.
