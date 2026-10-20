# Verifying nym_auth pseudonym proofs

A `circuit_zk` presentation carries **no credential**. It carries a
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
circuit_zk: this verifier was built without the zknative tag, so no nym_auth proof can be checked
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
    verifier_id: verifier.example
    circuits:
      allow:
        - config: known-offender-matching-ssc
          hash_circuit_id: 5f8c75ae5c3893ef6ab6a079628cb385ba85e95a85437d58570c455289d75729
          sig_circuit_id: 00513797c75b2eab1a9db75004977c15317d4e40c0db1d00674523431baa75cb
          block_enc_hash: 6983
          block_enc_sig: 4679
          artifact_path: /etc/vc/circuits/nym_auth-ssc.bin
          artifact_sha256: 92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f
          artifact_bytes: 1062842
  preferred_vp_formats:
    circuit_zk:
      circuit_id_values: ["urn:circuits:longfellow:nym_auth:v1"]
      circuit_proof_system_values: ["longfellow-libzk-v1"]
  trust:
    pdp_url: https://pdp.example/pdp     # BASE url; /evaluation is appended
```

Four separate things have to be right, and each fails differently. They are
separate on purpose: each one is a different question, and folding any two
together would make the answer to one depend on the other.

### `verifier_id` — the bare value, and two markers that are not prefixes

`SHA-256(verifier_id)` is `verifier_input`, the value that scopes every
pseudonym to this verifier. It is **configured**, never derived from
`client_id`.

It cannot be derived: `verifier_id_type` is agreed out of band in the trust
framework and is not on the wire, so there is nothing in a request to derive
it from — and the prefixed Client Identifier is the form the rulebook marks
MUST NOT.

```
SHA256("verifier.example")              = be6a6400…4a41   (MUST)
SHA256("x509_san_dns:verifier.example") = 6eae85a0…6bab   (MUST NOT)
```

Two strings look like a prefix and a colon and are **not the same kind of
thing**:

| value | what to configure |
|---|---|
| an `x509_san_dns` verifier | the dNSName alone — `verifier.example`, no prefix |
| a semantic verifier | the whole `semantic_id:<identifier>`, which *is* the identifier |

A value carrying `x509_san_dns:` is refused at startup. A `semantic_id:`
value is **correct and must not be stripped**; only a bare `semantic_id:`
with nothing after it is refused, because it names no verifier.

Getting this wrong does not produce an error. It produces a pseudonym no
other implementation reports.

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

### `preferred_vp_formats.circuit_zk` — offering nothing refuses everything

The circuit ids and proof systems a response may name come from *this*
configuration. A response naming anything else is refused:

```
circuit_id "urn:…" is not one this request offered
```

A verifier that offered **no** list offered nothing, and every response is
then refused. That is the intended reading rather than an oversight: the
alternative is the holder choosing what it is verified against.

### `trust.pdp_url` — the BASE url, and mandatory here

It is the PDP's **base** URL. The client appends `/evaluation` itself
(`BaseURL + DefaultEvaluationPath`), so configuring the evaluation endpoint
gives `…/evaluation/evaluation`, every request 404s, and every presentation
is refused — a failure that looks like a trust problem and is a typo.



The issuer key the circuit proves a signature under comes from the
presentation's own `x5chain`, which the **holder** sends. The PDP is the
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
circuit_zk: no trust evaluator is configured, so no issuer key can be trusted
```

Fail closed, deliberately not "nothing is trusted, carry on": a verifier
that cannot ask whether an issuer is trusted must not read its own silence
as a yes.

## Where the issuer key comes from

A `circuit_zk` presentation carries the issuer's certificate chain —
`x5chain`, leaf first, standard base64 DER, at most 8 certificates of at
most 4096 bytes each. The holder sends it, and at first reading that looks
like letting the holder choose what it is measured against. It is not,
because the two halves are checked separately:

- The **circuit** proves "this credential was signed by Q", for the Q given
  to it. A holder who substitutes a key it controls gets a proof about a
  credential that key signed — which is a credential it issued to itself.
- The **PDP** then says whether Q belongs to an issuer this verifier
  accepts — through the same `pkg/mdoc.VerifyIssuerChain` as a plain mdoc
  presentation's DS certificate. One implementation rather than two, so the
  two paths cannot drift into trusting different things. A self-signed key
  does not get a decision.

Neither half is sufficient alone, and either one failing refuses the
presentation. The `docType` the chain is evaluated for comes from the
**request**, never the response — a holder choosing it would be choosing the
trust policy it is judged under.

This reveals no more than a plain mdoc presentation already does: a DS
certificate identifies the issuer and says nothing about which credential or
which subject.

### The request the PDP actually receives

Worth writing out, because the action on the wire is **not** the role the
code sets. The verifier sets the role `credential-issuer`; `GetEffectiveAction`
in `pkg/trust` then derives the action from that role plus the docType, and
that derived value is what is sent:

```json
{
  "subject":  { "type": "key", "id": "<issuer URL from the leaf DS cert's URI SAN>" },
  "resource": { "type": "x5c", "id": "<same as subject.id>",
                "key": ["<standard base64 DER, leaf first>", "..."] },
  "action":   { "name": "mdoc-issuer" }
}
```

| | |
|---|---|
| `mdoc-issuer` | any mdoc docType, including `eu.europa.ec.eudi.nym_auth.1` |
| `mdl-issuer` | the `org.iso.18013.5.1.mDL` docType specifically |
| `credential-issuer` | a **looser** policy (fingerprint whitelist) — **not** this path |

That last row is the one to watch when writing policy: a rule written for
`credential-issuer` will never match a circuit_zk presentation, because the
verifier never sends that action for one.

There is **no `doc_type` in the context**. The docType selects the action
name and nothing else; the context carries only what `TrustOptions` adds,
and this path sets none. `resource.id` must equal `subject.id` or go-trust
rejects the request before sending it.

The leaf key must be P-256, because the circuit's arithmetic is. A key on
another curve cannot be a public input to it, so accepting one would mean
verifying against something the circuit never saw.

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
circuit_zk: this presentation arrived by redirect with response_mode "direct_post";
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
| `verifier.nym_auth is not enabled` | the request asked for `circuit_zk` and this verifier cannot answer |
| `cannot be used without a PDP` | `trust.pdp_url` is empty, so every issuer would be trusted |
| `no trust evaluator is configured` | no evaluator at all; no issuer key can be trusted |
| `is not trusted for docType` | the PDP declined the chain, or could not be reached |
| `the issuer key is on P-384` | the DS certificate's key is not P-256 |
| `is not one this request offered` | the response named a circuit or proof system outside `preferred_vp_formats` |
| `requires "direct_post.jwt"` | a redirect presentation whose response was not encrypted |
| `circuits.allow is empty` | enabled, but nothing is allowed, so nothing could verify |
| `the handover for this channel is pending shared vectors` | a delivery channel with no defined transcript |
| `response refused: <reason_code>` | the presentation's shape; the code is the shared conformance vocabulary |

The last one is worth expanding: a refused `circuit_zk` response names a
**stable reason code**, not message text, because the Rust matcher, the
Kotlin and Swift SDKs and this verifier all name the same failure the same
way. If a wallet and this verifier disagree about a response, the code is
what to compare across the two.

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
