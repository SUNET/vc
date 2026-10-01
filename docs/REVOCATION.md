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

An entry is keyed on `(status_list_uri, idx, backend)`. The backend is part
of the key because it is the routing dimension — the table records it
precisely because the URI alone does not say who owns an entry — and two
backends reusing one URI and index are two distinct entries, not one. It
does not make lookups ambiguous: revocation reads by identifier and narrows
in memory.

An entry is recorded only if it names both a list URI and a backend this
build can reach (`registry` or `status_service`). Either half missing means
the mapping could be written and never acted on — `SetCredentialStatus`
refuses an unknown backend rather than guessing, because guessing writes a
status into the wrong list — so the issuance fails and the batch's
allocations are released.

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
| mdoc | `status` in the MSO (draft Section 6.3) | yes — MSO only, see below |
| ZK mdoc | — | **refused**, see below |
| JWP (BBS) | the issuer protected header | not yet |
| W3C VC 2.0 | `credentialStatus` with `TokenStatusListEntry` | not yet — and off by default, see below |

A JWP carries its status in the issuer header rather than in a claim
deliberately: a claim would be one of the signed messages and so selectively
disclosable, and a revocation status a holder can decline to reveal is not
revocation. The verifier's status extraction reads claims, so it does not
find it there yet.

### An mdoc `status` DATA ELEMENT is not a revocation reference

Implementations that predate draft Section 6.3 put the reference in an
issuer-signed data element called `status` rather than in the MSO. The
verifier does not read it, and will not.

A data element is selectively disclosed: the holder chooses which to
present. So a revoked credential whose only reference lives there is simply
presented without it, and the verifier sees a credential that is not
revocable. Nor can the omission be detected — the MSO's `ValueDigests` name
every issuer-signed element by digest ID, never by identifier, so a verifier
can tell that elements were withheld but not which.

A check an adversary turns off by omitting a field is not a check. It only
ever caught a holder who chose to be caught, and leaving it in made vc's
revocation coverage look uniform across mdoc issuers when it is not. An
issuer that wants its mdocs revocable must put the reference in the MSO, as
vc's own issuance always has.

The element is still returned as the claim it is, under its
namespace-qualified key. What it may not do is answer the revocation
question: `GetClaims` reserves the bare `status` key for the MSO, because
that key is what every other format uses for the reference.
`mdoc.ExtractStatusReference` still reads the fallback for diagnostics
(`developer_tools/scripts/tsl_checker`), where the operator supplies the
document and the question is "where does this say its status lives".

### ZK mdoc presentations are refused, not passed

A ZK mdoc presentation proves statements about claims without revealing the
document, so the verifier never sees an MSO and there is no status to read.
Letting it fall through to the generic claims check would find no status and
read that as "not revocable", which lets a revoked credential verify —
`formatCanCarryStatus` refuses the format instead.

### Allocation happens in the issuer; recording happens in the apigw

`MakeSDJWT`, `MakeMDoc`, `MakeJWP` and `MakeVC20` each allocate a status
entry themselves and embed the reference in what they sign. Recording the
`(status_list_uri, idx) → subject` mapping is the **caller's** job, and only
the OpenID4VCI path in `handlers_issuer.go` does it.

That split is a trap for any new issuance entry point: calling one of those
gRPC methods and not recording produces a credential carrying a status
reference that nothing can ever set to INVALID, and burns a slot doing it.
`createCredentialViaOIDCRP` in `internal/apigw/apiv1/handlers_oidcrp.go` is
written that way, but it has no callers — the OIDC-RP callback stores
documents and returns a credential offer, and issuance then goes through the
ordinary OpenID4VCI path. A comment at the call site says what wiring it up
would require.

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

`status_list_uri` + `index` narrow the operation to one entry. Since an
entry is identified by all three of `(status_list_uri, idx, backend)`, that
pair can select more than one, and a request naming only the pair when it is
ambiguous is **refused** — `backend` says which. Acting on both would revoke
a credential nobody asked about.

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

`status_list_issuer` is also what a `kid`-only token resolves its key under.
A status list token need not carry `iss` (Section 5.1), and JWKS discovery
has nothing to discover from without an identity — so a conforming service
that signs with a `kid` and omits `iss` needs this set, or its lists cannot
be verified at all. It becomes the policy subject for such a token too:
the operator has said whose lists these are.

`status_list_issuer` alone is not always enough. It gives the
discovery-based resolver an identity to look for a JWKS under, and a status
service's status-list signing key need not be published there at all.
siros-status-service is one such case: its AS JWKS exists for access-token
verification while the status-list key is separate with no JWKS endpoint, so
discovery finds nothing and every external list fails to verify.
`status_list_key_file` **pins** the key. The pin is scoped: it covers a
token with no `iss`, and one whose `iss` is exactly `status_list_issuer`.
If the service signing your lists does emit an `iss`, set
`status_list_issuer` to that value too, or the pin will not apply.

It is scoped rather than global because a deployment may run the registry
alongside an external service, and those lists are signed by different keys
— a global pin made the external key answer for registry tokens and broke
them the moment a key file was configured.

Within its scope the pin is **enforcing**, not a fallback: such a token
verifies against the pinned key even when it carries an `x5c` or `jwk` of
its own. Naming a key is a statement about which key signs these lists, so
a service that rotated its key — or anyone who minted a token with their
own `jwk` — must not be accepted on the strength of what the token carries.

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

The subject is the token's `iss` claim when it has one, and otherwise the
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

### What happens when the PDP cannot judge a token

This narrowing applies **only when `verifier.trust.pdp_url` is configured**.
Without one the evaluator allows everything, so narrowing would buy no
policy decision while still refusing the resolver — and vc's own registry
issues status list tokens with no `kid`, `jwk` or `x5c`, so a default
registry-only deployment would stop verifying its own lists.

`JWTTrustVerifier` resolves key material from the token's own header and
works on JWTs. Two kinds of token give it nothing to judge:

- a JWT carrying no `x5c`, `jwk` or `kid`. siros-status-service publishes
  lists like this;
- a CWT, which it cannot read at all.

Such a token verifies against the pinned `status_list_key_file` if one
applies, and is **refused** otherwise. (A token the PDP *can* judge still
goes through it — unless a pin covers it, in which case the pin decides; see
above.) It does not fall back to the generic
key resolver: that resolver answers "is this the key that identity
publishes", never "may this party publish these statuses", so reaching it
would let a signer get to a status value with no policy decision — by
omitting a header, or simply by serving the same list as a CWT.

So a deployment with a trust framework and CWT status lists must pin the
signing key. That pin is an operator statement standing in for the decision
the PDP cannot make; it is not a way around the PDP for tokens it *can*
judge, which always go through it.

### A PDP plus vc's own registry: the verifier refuses to start without a pin

The registry is the case where this bites hardest, because its tokens can
*never* be judged — it signs them with no `kid`, `jwk` or `x5c`. So a
verifier configured with both `verifier.trust.pdp_url` and a local
`registry.public_url` fails every local status check, and `fail_open`
defaults to **true**, which reads each failure as "not revoked". A revoked
credential is accepted, permanently, with nothing but a per-request log
line.

The verifier therefore **refuses to start** in that configuration unless
the registry is pinned:

```yaml
verifier:
  trust:
    pdp_url: https://pdp.example.com
  revocation:
    status_list_issuer: https://registry.example.com   # == registry.public_url
    status_list_key_file: /etc/vc/registry-status.pub.pem
```

`status_list_issuer` must equal `registry.public_url` exactly: the registry
puts that value in its tokens' `iss`, and the pin only covers a token whose
`iss` matches (or that carries none). A key file on its own does not apply.

The check runs at config load, while the `registry:` and `verifier:`
stanzas are both still present — a moment later the loader nils out the
sections a service does not own, and the verifier can no longer see that a
registry exists at all.

That is also its limit. It only covers a **shared** config file. A verifier
given its own file with no `registry:` stanza cannot be checked: nothing in
that file says a local registry is in play, so pin it by hand with the two
settings above.

A standalone verifier that really does see only external lists is
unaffected either way: those lists carry their signer in the token and are
judged by the PDP.

A deployment running the registry *and* an external service under a PDP has
one pin to give, and it must go to the registry: those tokens have no other
route. The external service's lists then need `x5c` or `jwk` in their
tokens so the PDP can judge them.

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
