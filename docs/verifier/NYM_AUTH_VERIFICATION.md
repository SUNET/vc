# Verifying nym_auth pseudonym proofs

A `zkp_req` presentation carries **no credential**. It carries a
zero-knowledge proof that some credential, signed by some issuer, satisfies
the predicates this verifier asked for — and, where the request asked for
one, a **pseudonym**: a stable identifier for the holder that is scoped to
this verifier and to nobody else.

That is the whole point, and it is also why almost everything below is about
refusing things. A pseudonym is only meaningful if every verifier computes
it the same way; a verifier that gets any input wrong produces a value that
matches nothing, and a value that matches nothing reads as *this is not the
person you are looking for*. **The failure mode of this feature is a wrong
answer about a person, not an error anyone sees.** Nearly every refusal in
this document exists to turn one of those silent wrong answers into a loud
one.

The counterpart on the issuing side is
[`docs/issuer/SEED_COMMITMENTS.md`](../issuer/SEED_COMMITMENTS.md), which
covers the seed, the commitment and recovery.

## Nothing verifies without the `zknative` build

The proof check is cgo, behind the `zknative` build tag, against
zk-cred-longfellow's C ABI. The default build of this repository is
`CGO_ENABLED=0` and fully static, and in that build **no nym_auth proof can
be checked at all**:

```
zkp_req: this verifier was built without the zknative tag, so no nym_auth proof can be checked
```

It refuses rather than returning a verified-looking zero value. Everything
upstream of that point is real — the request's own checks, the response's
shape, its binding to the offer, the trust decision on the issuer — so a nil
error there would hand all of it back as a successful verification of a
proof nothing looked at.

Build it with:

```sh
make build-verifier-zknative     # needs the native libraries staged
```

If you see that message in production, the deployment is running the wrong
binary. There is no configuration that turns this on.

## Turning it on

```yaml
verifier:
  nym_auth:
    enable: true
    verifier_id: x509_san_dns:verifier.example
    circuits:
      allow:
        - system_id: urn:circuits:longfellow:nym_auth:v1
          config: known-offender-matching-ssc
          hash_circuit_id: 5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729
          sig_circuit_id: 00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb
          block_enc_hash: 6983
          block_enc_sig: 4679
          artifact_path: /etc/vc/circuits/nym_auth-ssc.bin
          artifact_sha256: 92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f
          artifact_bytes: 1062842
  preferred_vp_formats:
    zkp_req:
      system_id_values: ["urn:circuits:longfellow:nym_auth:v1"]
      proof_system_values: ["longfellow-libzk-v1"]
  trust:
    pdp_url: https://pdp.example/pdp     # BASE url; /evaluation is appended
  presets:
    "Pseudonym":
      credentials:
        nym_auth:                        # a common.credential_metadata scope
          format: zkp_req
          validate: nym_auth             # optional, and worth having
          req:
            - fn_id: pseudonym
              return: nym
              params:
                config: known-offender-matching-ssc
                ver: 1
                prf: sha-256
```

An allowlist entry names the proof system it belongs to as well as the
pseudonym configuration, and both are required. `system_id` is the value
a presentation states — the catalog alias, not the catalog id and not
the proof-system name — and it is what lets one verifier allow
Longfellow and Vega for the same configuration:

```yaml
      allow:
        - system_id: urn:circuits:longfellow:nym_auth:v1
          config: known-offender-matching-ssc
          # ... the Longfellow artifact and its four parameters
        - system_id: urn:circuits:vega:nym_auth:v1
          config: known-offender-matching-ssc
          # ... the Vega artifact
```

Offer both in `system_id_values` and the wallet chooses between them.
This Verifier refuses any `system_id` it did not offer, and refuses at
startup any entry whose `system_id` it does not recognise rather than
guessing a default.

Five separate things have to be right, and each fails differently. They are
separate on purpose: each one is a different question, and folding any two
together would make the answer to one depend on the other.

### `verifier_id` — exactly as published, prefix and all

`SHA-256(verifier_id)` is `verifier_input`, the value that scopes every
pseudonym to this verifier. It is **configured**, never derived from
anything on the wire.

Hash it **exactly as the Verifier publishes it**. Nothing is stripped and
nothing is normalised — not case, not a trailing dot:

| verifier | configure |
|---|---|
| an `x509_san_dns` verifier | `x509_san_dns:verifier.example` — **with** the prefix |
| a semantic verifier | `semantic_id:<identifier>` — the whole string |

```
SHA256("x509_san_dns:verifier.example") = 6eae85a0…6bab   (MUST)
SHA256("verifier.example")              = be6a6400…4a41   (the bare DNS name, which is NOT a verifier_id)
```

**This reversed on 2026-10-20.** Until rulebook v0.4 the bare DNS name was
hashed and the prefixed form refused, so anything written before that date
says the opposite. The archive circuits settle it: their reference
`pseudonym.json` pairs `client_id` `x509_san_dns:verifier.example` with
`verifier_input` `6eae85a0…`.

**A value that is neither form is refused at startup**, naming both and —
when it looks like a hostname — the value you probably meant. That check
matters more than it sounds: the bare DNS name was the *correct* value until
the reversal, so every configuration written before it carries one. Without
the check such a deployment starts cleanly and produces pseudonyms no other
implementation reports — a wrong answer about a person, with no error
anywhere.

```
verifier_id "sirosid-gdc-vc-verifier.fly.dev" starts with neither
"x509_san_dns:" nor "semantic_id:", and rulebook v0.4 defines no other
form; it looks like a DNS name, so the verifier_id is probably
"x509_san_dns:sirosid-gdc-vc-verifier.fly.dev"
```

Nothing is normalised, case included: `X509_SAN_DNS:` is refused too. The
only other values refused are ones naming no verifier at all — an empty
string, or a marker with nothing after it.

### The circuit allowlist — nothing outside it is ever loaded

An entry states what a build *is*: which pseudonym configuration it
implements, its two circuit ids, its Ligero block parameters, and the exact
size and digest of the decompressed artifact. The loader checks the artifact
against the entry and refuses anything else **before parsing it**.

`config` is first-class because it is how a request selects a build, and
because the configuration is baked into the circuit: the domain separator is
`"nym_auth/v1/" + config`, so `…-ssc` and `…-psc` produce **different
pseudonyms from the same inputs**. Nothing in an artifact says which one it
is, so the entry is that statement — and an entry naming the wrong
configuration verifies proofs against a pseudonym function nobody asked for.

Enabled with an empty allowlist is refused outright:

```
verifier.nym_auth is enabled but verifier.nym_auth.circuits.allow is empty,
so no proof could be verified
```

"On" and "cannot check a single proof" is not a state anyone means to
configure. The whole block — `verifier_id`, the allowlist, every artifact —
is validated at startup rather than at the first presentation, where an
operator would see a refused proof and have no reason to suspect the
configuration.

### `preferred_vp_formats.zkp_req` — offering nothing refuses everything

The circuit ids and proof systems a response may name come from *this*
configuration. A response naming anything else is refused:

```
system_id "urn:…" is not one this request offered
```

A verifier that offered **no** list offered nothing, and every response is
then refused. That is the intended reading rather than an oversight: the
alternative is the holder choosing what it is verified against.

### The preset — `req`, and the two keys that are not the wire's

A `zkp_req` request asks for the output of functions. Everything it yields
is named in `req`, so a preset with an empty one asks for nothing, and a
wallet answers it with nothing.

Two key names differ from the rulebook on purpose, and both fail silently
if you follow the rulebook here instead of this page:

| rulebook (the wire) | preset (this configuration) |
|---|---|
| `_req` | **`req`** |
| `fn_id` | `fn_id` — same |

Configuration is deliberately not loaded strictly, so an unknown key is not
an error anywhere else in this file; `_req` would simply leave the preset
with no items. That one is now refused at startup:

```
verifier.presets."Pseudonym".credentials."nym_auth" asks for format zkp_req
but its req is empty, so the request would ask the wallet for nothing; the
preset key is `req` (the wire member it becomes is `_req`)
```

`ver` and `prf` are REQUIRED parameters of `pseudonym` in rulebook v0.4.
`sha-256` is the one defined over a stored mdoc. A preset missing either is
well formed and unsatisfiable: wallets decline it.

`meta.source_format` is **derived, never configured.** It names the stored
attestation the proof is made over, which is the scope's own
`common.credential_metadata` format — the credential the wallet actually
holds. A second place to state it is a second place for the two to
disagree, and a disagreement surfaces as a wallet refusing the request
rather than as a configuration error. A request built without one is
refused by the wallet's matcher as `invalid_meta` before it reads anything
else.

`validate: nym_auth` is optional and checks the preset against the rulebook
at startup, where you can still do something about it. It is the same set
of rules the shared conformance vectors state, so a preset that passes it
is one the other implementations agree is satisfiable — with one deliberate
exception: `known-offender-matching-psc` is refused **whatever the allowlist
says**. A psc is a commitment the holder already knows, and nothing yet
specifies how a Verifier conveys one to a wallet, so a preset naming it
cannot be sent even by a deployment that has the circuit. Adding one does
not lift the refusal; a specified mechanism would.

An age check is a second item in the same preset, not a second preset:

```yaml
          req:
            - fn_id: pseudonym
              return: nym
              params:
                config: known-offender-matching-ssc
                ver: 1
                prf: sha-256
            - fn_id: age_check
              return: age
              params:
                ge: "2008-10-10"
                le: "2013-10-09"
```

`ge`/`le` are full dates and bound a birth-date range, and the range must
span at least 365 days: a narrower one is an exact birth date wearing a
predicate's clothes.

### `trust.pdp_url` — the BASE url, and mandatory here

It is the PDP's **base** URL. The client appends `/evaluation` itself
(`BaseURL + DefaultEvaluationPath`), so configuring the evaluation endpoint
gives `…/evaluation/evaluation`, every request 404s, and every presentation
is refused — a failure that looks like a trust problem and is a typo.



The issuer key the circuit proves a signature under comes from the
presentation's own `issuer_key_set`, which the **holder** sends. The PDP is the
only thing that says that key belongs to a real issuer.

Elsewhere in this verifier an empty `pdp_url` means "allow all" — keys are
resolved and always considered trusted, which is a defensible mode for a
format where the holder cannot supply the key it is measured against. **Here
it removes the only check there is.** With allow-all a holder can sign a
certificate for itself, present it as the issuer, and satisfy "signed by Q"
with its own key — which means it chooses its own pseudonym. A flagged
person then presents a value that matches nothing and reads as innocent.

So nym_auth refuses to start without one:

```
verifier.nym_auth is enabled but verifier.trust.pdp_url is empty, so every
issuer would be trusted; nym_auth takes the issuer key from the holder's own
certificate chain and cannot be used without a PDP
```

and refuses again at the point of use, which is what cannot be bypassed. A
verifier with no evaluator at all refuses the same way:

```
zkp_req: no trust evaluator is configured, so no issuer key can be trusted
```

Fail closed, deliberately not "nothing is trusted, carry on": a verifier
that cannot ask whether an issuer is trusted must not read its own silence
as a yes.

## Where the issuer key comes from

A `zkp_req` presentation carries the issuer's certificates in
`issuer_key_set` — leaf first, DER, at most 8 of at most 4096 bytes each by
the shared shape. **For the Longfellow system this verifier requires exactly
one**: the archive circuits take a single Document Signer, and on circuit
semantics the archive wins over the shared shape. More than one would mean
choosing which to treat as the leaf, and the circuit has no notion of a
chain to walk.

The holder sends it, and at first reading that looks like letting the holder
choose what it is measured against. It is not, because the two halves are
checked separately:

- The **circuit** proves "this credential was signed by Q", for the Q given
  to it. A holder who substitutes a key it controls gets a proof about a
  credential that key signed — which is a credential it issued to itself.
- The **PDP** then says whether Q belongs to an issuer this verifier
  accepts, through the same `pkg/mdoc.VerifyIssuerChain` as a plain mdoc
  presentation's DS certificate. A self-signed key does not get a decision.

Neither half is sufficient alone, and either one failing refuses the
presentation. The `docType` the key set is evaluated for comes from the
**request**, never the response.

This reveals no more than a plain mdoc presentation already does: a DS
certificate identifies the issuer and says nothing about which credential or
which subject.

The leaf key must be P-256, because the circuit's arithmetic is. A key on
another curve cannot be a public input to it, so accepting one would mean
verifying against something the circuit never saw.

## `proof_time` — the prover's clock, inside your window

Every presentation carries `proof_time`: the moment the prover made the
proof, as the exact 20-byte `YYYY-MM-DDThh:mm:ssZ` form. Required for
`mso_mdoc`, because every approved circuit there checks the MSO validity
period.

**It is the prover's value and the verifier uses it.** That sounds wrong
until you see why it has to be: the circuit binds all 20 bytes of T into its
public inputs, so prover and verifier must use the *same second*, and only
the prover knows which second it proved at. A verifier that substituted its
own clock would produce public inputs no prover matches, and every real
presentation would fail — indistinguishably from a bad proof.

What makes accepting the prover's value safe is the window:

```yaml
verifier:
  nym_auth:
    proof_time_skew_seconds: 60     # how far ahead of our clock we accept
    proof_time_max_age_seconds: 600 # how far behind
```

Those are the shared recommendations and the defaults when unset. They are
recommendations rather than protocol constants — the tolerance is yours —
but a deployment that has not thought about it should behave the way other
implementations assume.

Without a window a holder could replay a proof made long ago, or one made
with a clock set forward. Outside it is **refused, never clamped**:
verifying against a T the prover did not use cannot succeed, and would
report the wrong reason when it failed. The refusal names the observed
deviation and the limit, because the next question is always "by how much".

What the window does **not** do is check credential status. The proof
checks the MSO's validity period at T, and the window bounds how far T may
be from now — so a credential that has been revoked but has not expired
still produces a proof this verifier accepts. Bounding the age shortens
the interval in which that is possible; it does not close it, and no
revocation check runs on this path. Nor is the window replay protection:
the nonce in the transcript is what binds a proof to one request.

Only the exact form is accepted. A fractional second, a numeric offset, a
lower-case `t` or `z`, or a date that does not exist are all refused —
`2026-02-30T00:00:00Z` is well-formed and denotes nothing.

## Two handovers, and why the channel matters

The proof is bound to a `SessionTranscript`, and there are two of them:

```
DC API    ["OpenID4VPDCAPIHandover", SHA-256(cbor([origin, nonce, thumbprint]))]
redirect  ["OpenID4VPHandover",      SHA-256(cbor([clientID, nonce, thumbprint, responseURI]))]
```

A wallet built **one** of them. Verifying against the other produces an
opaque proof failure, which sends whoever debugs it to look at the circuit.
The channel is therefore chosen by how the response actually arrived — a
`navigator.credentials.get` call, or a POST to `response_uri` from a scanned
QR or a link — and never by configuration.

A channel with no transcript builder is refused rather than given one of
this verifier's invention.

### Over a redirect the response must be encrypted

A pseudonym is a stable identifier for a person across this verifier's
sessions. Sent to `response_uri` in the clear it is readable by anything on
the path, so nym_auth requires `direct_post.jwt` there:

```
zkp_req: this presentation arrived by redirect with response_mode "direct_post";
nym_auth requires "direct_post.jwt" there, because a pseudonym sent to
response_uri in the clear is readable by anything on the path
```

The DC API channel is not subject to this: a response returned inside
`navigator.credentials.get` never crosses the network, and its handover
takes a null reader-key thumbprint for exactly that case.

## Reading a refusal

| message contains | what it means |
|---|---|
| `built without the zknative tag` | wrong binary; no proof can be checked |
| `verifier.nym_auth is not enabled` | the request asked for `zkp_req` and this verifier cannot answer |
| `cannot be used without a PDP` | `trust.pdp_url` is empty, so every issuer would be trusted |
| `no trust evaluator is configured` | no evaluator at all; no issuer key can be trusted |
| `is not trusted for docType` | the PDP declined the chain, or could not be reached |
| `the issuer key is on P-384` | the DS certificate's key is not P-256 |
| `is not one this request offered` | the response named a circuit or proof system outside `preferred_vp_formats` |
| `requires "direct_post.jwt"` | a redirect presentation whose response was not encrypted |
| `circuits.allow is empty` | enabled, but nothing is allowed, so nothing could verify |
| `the handover for this channel is pending shared vectors` | a delivery channel with no defined transcript |
| `starts with neither` | `verifier_id` is not one of the two forms v0.4 defines |
| `is the pre-v0.4 name` | configuration still says `circuit_zk` / `circuit_id_values` / `circuit_proof_system_values` |
| `takes exactly 1` | `issuer_key_set` carries more than the Document Signer certificate (both systems take exactly one) |
| `is outside this verifier's window` | the prover's `proof_time` is beyond the skew or the max age; the detail names both limits |
| `proof_time_form` / `proof_time_not_tdate` | `proof_time` is not the exact 20-byte tag-0 form |
| `zkp_req_*` / a matcher reason code | the presentation itself — see below, where these are **codes**, not message text |

The last row is a different kind of entry from the ones above it, and is
worth expanding. The rows above are text you can grep a startup log for. A
refused presentation is not text at all: it comes back to the wallet as
HTTP 400 whose `title` is a **stable reason code** and whose `details` is
the human sentence, and it is logged here at warn level with `scope=`,
`code=` and `detail=` as separate structured fields, under a message
naming the step that refused it (`zkp_req presentation refused`,
`zkp_req proof_time refused`, `zkp_req proof did not verify`, ...). So
grep the `code`, not the sentence — the sentence is free to be reworded
and the code is not.

The vocabulary is shared: this path's own codes are `zkp_req_no_presentation`,
`zkp_req_proof_time_missing`, `zkp_req_proof_time_out_of_range`,
`zkp_req_wrong_channel`, `zkp_req_issuer_key_set_empty`,
`zkp_req_issuer_key_set_size`, `zkp_req_issuer_key_not_a_certificate`,
`zkp_req_issuer_not_trusted`, `zkp_req_issuer_key_wrong_curve`,
`zkp_req_issuer_key_not_ecdsa`, `zkp_req_proof_did_not_verify`,
`zkp_req_no_pseudonym_for_handle` and `zkp_req_nothing_checked`, and a
response refused on its **shape** carries the shared matcher's own reason
code unchanged — the Rust matcher, the Kotlin and Swift SDKs and this
verifier all name that failure the same way. If a wallet and this verifier
disagree about a response, the code is what to compare across the two.

A verifier that is misconfigured, or built without the `zknative` tag, is
deliberately **not** in this vocabulary: it has not refused a presentation,
it cannot judge one, so those stay 5xx and unclassified rather than telling
a wallet author its presentation is bad when the fault is ours.

## What this does not do

- **It does not link a pseudonym to a person.** That is the issuer's side,
  and deliberately so — see `docs/issuer/SEED_COMMITMENTS.md`. Whoever can
  run the recovery tool can link any pseudonym to a person; this verifier
  cannot.
- **It does not decide policy from the response.** Every input to the check
  is this verifier's own: the transcript from its session, the age bounds
  from its request, `verifier_input` from its configuration, the `docType`
  from its query. The request builder refuses anything taken from the
  response, which is most of why it exists.
- **It does not accept a predicate-only request.** The proof is one proof
  over the whole request, and the only verification path is a pseudonym
  item's check — so a request asking only for an age predicate has nothing
  that checks the proof, and is refused rather than believed.
