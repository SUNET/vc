# Seed-backed commitment claims

A credential claim may carry a **commitment over a per-subject seed**
instead of a value from a data source. The issuer holds the seed; the
credential carries `commit(seed)` and never the seed itself.

The point of holding the seed is that the issuer can reproduce it later,
and so reproduce anything derived from it — which is what lets a pseudonym
presented to a Relying Party be mapped back to a person.

Nothing here is specific to one credential type. The first consumer is the
EUDI `nym_auth` attestation, whose `ssc` element is SHA-256 over a 16-byte
seed, but the claim path, the credential it belongs to, the digest and the
seed length are all configuration.

## What the issuer does, and what it does not

It **generates** the commitment and writes it. That is the whole of it.

- **It delivers the seed only when the claim asks it to.** By default a
  credential carries the commitment and nothing else, which is the
  original capability and is unchanged. Setting `deliver: true` on a
  commitment claim opts that claim in, and then the seed travels in the
  response-level `credential_metadata` object of the OpenID4VCI 1.1
  Credential Response, under `org.siros.secret_seed`, keyed by namespace
  (privatedata-spec §5A).

  Delivery brings requirements with it, all refused rather than
  degraded. The response MUST be JWE-encrypted, which means the wallet
  must have ASKED — so the issuer advertises the seed NAMESPACES in its
  metadata, names only and never values, and a request that did not ask
  is refused before anything is issued. It MUST carry a
  `notification_id`, which is how a wallet reports a failed commitment
  check. And the seed is never persisted, logged, traced, or put in
  display or claims metadata.

  **This issuer must itself support response encryption**, which means
  `apigw.issuer_metadata.credential_encryption.keys` must hold at least
  one key. Without it a delivering scope is a deadlock — a wallet asking
  for encryption is refused for lack of support, and one not asking is
  refused for the seed — so startup refuses that configuration rather
  than advertising a credential nobody can obtain. See step 5 below.

  (An earlier version of this document said there would never be a
  response member for the seed, on the reasoning that a derived seed is
  recomputable and so need never be handed over. That decision was
  reversed: a holder has to be able to check the commitment it was given,
  and a psc-style configuration has no issuer-side seed to recompute.)

## Configuration

Two blocks. A seed source on the **apigw**:

```yaml
apigw:
  seeds:
    primary:
      model: derived
      secret_path: /etc/vc/seed/issuer.key   # base64url; >= 32 bytes DECODED
      # seed_bytes: 16                       # default, and the minimum
```

Under `apigw`, not `issuer`. The seed is derived and its commitment
injected before the issuer service is called, so the issuer receives an
ordinary claim and never sees the derivation secret. A secret that only
one service needs belongs in that service's configuration — keeping it
where it is not used is how it ends up mounted somewhere it need not be.

`model: derived` is the only model. A `stored` one — a random seed drawn
on first sight of a subject and kept — was described here once and never
implemented, because it needs a per-subject store that nothing on this
path has.

The secret itself is never written in `config.yaml` — setting
`apigw.seeds.<name>.secret` there has no effect and startup still
refuses, because that key is read from the **secrets file** and nowhere
else. Either mount the secret and point `secret_path` at it, as above,
or put it in the secrets file:

```yaml
apigw:
  seeds:
    primary:
      secret: <base64url>                    # >= 32 bytes DECODED
```

Exactly one of the two. Both, or neither, is refused at startup rather
than resolved by precedence: a deployment with two sources of truth for
this secret cannot tell which one is live, and an operator editing the
half that is not would see no effect at all.

and, per credential, the claims that carry a commitment:

```yaml
common:
  credential_metadata:
    nym_auth:
      format: mso_mdoc
      mddl_url: https://registry.siros.org/sirosfoundation/nym_auth.mdoc.json
      commitments:
        ssc:
          seed: primary
          subjects:
            - issuing_country
            - personal_administrative_number
          # commit: sha-256     # default, and the only registered function
          # context: ""         # default; see below before setting one
          # encoding: base64    # default by format; see below
```

A credential with no `commitments` block is issued exactly as it is today.

**Formats.** Commitments are implemented for `mso_mdoc` and SD-JWT VC.
Configuring one on any other format is refused at startup.

The W3C formats are refused for a specific reason rather than for want of
effort: `MakeVC20` signs the RDF canonical form, where a property the
credential's JSON-LD contexts do not define expands to a relative predicate
and is dropped, while `ToCompactJSON` returns the original JSON unchanged.
A commitment at an undefined term would therefore be *visible in the issued
credential and not covered by the proof over it* — alterable without
invalidating the signature. Supporting them means resolving commitment
paths against the pinned contexts and refusing undefined or non-absolute
predicates, which belongs with the JSON-LD context handling rather than
here.

### `subjects` — what "the same person" means

`subjects` is an **ordered list** of paths into the document data the
issuer receives, naming the stable identifiers the seed is derived from.
They are the only inputs that separate one person's seed from another's,
so what they point at decides what "the same person" means for every
pseudonym built on this credential.

A list rather than one path because one identifier is frequently not an
identifier on its own: a national personal number is unique within its
country and a document number within its scheme. A deployment issuing a
Swedish PID to Swedish residents may configure the personnummer alone; one
issuing across member states configures the issuing country *and* the
personnummer, or two people who share a number in different populations
share a pseudonym.

**Order is part of the derivation.** `[a, b]` and `[b, a]` are different
seeds, so reordering the list repseudonymises everyone exactly as changing
the secret does. A one-element list derives precisely what that identifier
derived on its own, so adding a discriminator to an existing deployment is
a repseudonymisation and nothing else is.

For `mso_mdoc` the document data is flat and keyed by element identifier,
so the path is the element identifier — including one containing dots,
which is read as a single key and not as a descent. For every other format
a dotted path descends into the JSON object.

Each path is read from the document data **as received**, before any
commitment is written into it. A path naming another commitment's claim
path therefore refuses rather than deriving a seed from a value this
issuer just computed.

For `mso_mdoc`, the claim path must be an element the schema declares. The
namespace-qualified spelling is accepted and normalised to the bare element
identifier, because that is what an mdoc document is keyed by — writing the
qualified path verbatim would be dropped by the signer. A
signer emits the elements its schema declares and ignores anything else in
the document, so an undeclared target would inject cleanly and issue a
credential with no commitment in it. The apigw refuses that at startup,
where it has the schemas; the issuer refuses it at issuance, where it
receives them inline.

A path that resolves to nothing, to a non-string, or to an empty string
**refuses the issuance**. There is no fallback and no skipping. Deriving
over `""` would give every subject whose identity failed to resolve the
same seed; dropping the entry instead would be worse still, because
`[issuing_country, pan]` with no country present would then derive what
`[pan]` derives — handing a subject the pseudonym of a different subject
in a single-identifier deployment, silently, which is exactly the failure
these identifiers exist to prevent.

### `context` — leave it empty

`context` separates populations that must not share seeds. Empty is the
right default, because a subject has **one** seed: two credential types
issued to the same person have to lead back to the same person, and they
would not if the credential configuration were part of the derivation.

Setting it is irreversible in the same way the secret is: every commitment
written under one context is unrelated to the same subject's commitment
under another.

### `encoding`

How the commitment bytes are written into the document data. The default
is not a preference, it is what the format's carrier accepts:

- `mso_mdoc` → `base64`. A `bstr` element arrives as JSON and is decoded as
  standard base64. Setting `hex` against a `bstr` target is refused, at
  startup and at issuance, because it does not fail on its own: a
  64-character hex commitment is itself valid base64, so it would decode to
  48 bytes of nothing and be signed as the commitment, and nothing
  downstream could tell.
- everything else → `hex`, lowercase, which is what the `nym_auth` circuits
  read from an SD-JWT disclosure.

A commitment is injected as a JSON string, so for `mso_mdoc` only `bstr`
and `tstr` elements may be targets. Anything else is refused at startup:
`int` and `uint` fail the conversion after a revocation entry has already
been allocated, and `bool`, `array` and `map` do not fail at all — the
value passes through and is signed as a CBOR text string where the schema
promises something else, which only a verifier ever discovers.

In a nested format, two commitment paths where one is nested under the
other (`a` and `a.b`) are refused for the same reason: the outer is written
as a string, so the inner could never be written at all.

For SD-JWT VC the target must be a claim the **type metadata declares with
`sd: always`**. Only those become disclosures — anything else is signed in
the clear, so a misspelled or undeclared commitment path is not *missing*
from the credential, it is issued permanently in a form the holder cannot
withhold. That is the one outcome this feature must never produce: the
commitment is a stable identifier for its holder, and the wallet's ability
to keep it back is the entire protection.

Checked at startup against the configured VCTM and again at issuance
against the one the request carries.

Claims a format's signing layer writes for itself are refused as targets
too, since it writes them *after* this document is parsed — a commitment
there is injected and then silently replaced, and the credential carries
the envelope value instead. For SD-JWT VC that is `iat`, `nbf`, `exp`,
`iss`, `jti`, `vct`, `vct#integrity`, `cnf` and `status`; for the W3C
formats it is the subject's `id`. The root segment is what counts, because
`status` is assigned as a whole object and takes `status.value` with it.

## A worked example: `nym_auth` with seed delivery

Everything a deployment needs for a `nym_auth` credential that carries a
commitment **and** hands the wallet the seed to open it. Hostnames,
scope names and paths are **placeholders** — replace them.

### 1. The seed source (apigw)

```yaml
apigw:
  seeds:
    primary:
      model: derived
      secret_path: /etc/vc/seed/issuer.key   # base64url; >= 32 bytes DECODED
      # seed_bytes: 16                       # default, and the minimum
```

### 2. The credential, its schema, and the commitment

```yaml
common:
  credential_metadata:
    nym_auth:                                 # <- the scope/configuration id
      format: mso_mdoc
      mddl_file_path: /etc/vc/mddl/nym_auth.mdoc.json
      commitments:
        ssc:
          seed: primary
          subjects:                           # ORDER is part of the derivation
            - issuing_country
            - personal_administrative_number
          deliver: true                       # hand the SEED to the wallet
          # namespace: org.siros.nym_auth     # default
          # commit: sha-256                   # default
          # encoding: base64                  # default for mso_mdoc
```

`deliver: true` is the whole difference between "the credential carries a
commitment" and "the wallet can prove with it". Leave it out and nothing
about the earlier behaviour changes.

### 3. The MDDL must declare the claim

An mdoc signer emits the elements its schema declares and ignores
anything else, so a commitment path the schema does not declare would
inject cleanly and issue a credential with no commitment in it:

```json
{
  "format": "mso_mdoc",
  "docType": "eu.europa.ec.eudi.nym_auth.1",
  "claims": {
    "eu.europa.ec.eudi.nym_auth.1": {
      "ssc": { "mandatory": true, "value_type": "bstr" }
    }
  }
}
```

`format` is required: `LoadMDDLSchema` refuses a schema without it, and
a file copied from here without that member fails startup with
`unsupported MDDL format: ""`.

For SD-JWT VC the VCTM must declare the claim **`sd: always`** instead:
a commitment the holder cannot withhold is not a pseudonym.

### 4. The configuration must be offered

`nym_auth` has to appear in `apigw.issuer_metadata` as a credential
configuration. A scope that delivers a seed and is not offered **refuses
at startup** rather than being silently unreachable.

### What the issuer then publishes and sends

Issuer metadata gains, for that configuration, the namespace NAMES:

```json
"credential_metadata": {
  "org.siros.secret_seed": { "namespaces": ["org.siros.nym_auth"] }
}
```

and the Credential Response — **only** when the wallet requested
`credential_response_encryption` — carries the seed itself:

```json
"credential_metadata": {
  "org.siros.secret_seed": { "org.siros.nym_auth": "<32 lowercase hex>" }
},
"notification_id": "<minted>"
```

A request without `credential_response_encryption` **fails**. It is not
downgraded to issuing without the seed: that would hand the wallet a
credential whose commitment it can never open, and it would find out
when a proof was needed rather than at issuance.

## DEPLOYMENT NOTES

What a build of this needs. Written as a brief for whoever owns the
environment, not as something this repository configures.

**Build inputs (issuer side).** Nothing special: the ordinary vc build.
Seed derivation and delivery are pure Go, need no cgo and no build tag.

**Config keys.** `apigw.seeds.<name>` (`model`, and exactly one of
`secret_path` or the secrets-file `secret`); `common.credential_metadata.<scope>.commitments.<claim>`
(`seed`, `subjects`, `deliver`, optional `namespace`); the scope present
in `apigw.issuer_metadata`.

**Secrets.** One: the derivation secret, base64url, **>= 32 bytes
decoded**. Either a mounted file (`secret_path`) or
`apigw.seeds.<name>.secret` in the secrets file — never both, and never
inline in `config.yaml`. It is **permanent**: every commitment ever
written under it is a function of it, so it must be backed up somewhere
that survives the host, and rotating it repseudonymises everyone.

**Wallet requirement.** The wallet MUST request
`credential_response_encryption`, or issuance fails. The namespace
advertisement in issuer metadata is what tells it to.

**Issuer requirement.** Asking is not enough on its own: this issuer
must support response encryption too, which means at least one key in
`apigw.issuer_metadata.credential_encryption.keys`. Without it a
delivering scope cannot be issued at all — a wallet that asks is
refused for lack of support, one that does not is refused for the
seed — so a delivering scope on an issuer with no keys is refused at
startup rather than advertised. If you are enabling `deliver: true` on
an issuer that has never done JWE, that key is the prerequisite:

```yaml
apigw:
  issuer_metadata:
    credential_encryption:
      keys:
        - private_key_path: /etc/vc/enc/issuer-enc.pem   # P-256
```

**Ports, URLs, env vars.** Unchanged by this feature.

**Verifier side (when the nym_auth verifier lands).** Not needed to
issue, listed so it can be planned: a cgo build with `-tags zknative`
and the native ZK libraries staged under `third_party/`, pinned by
revision; `zk_circuits` sources pointing at the circuit catalog; and an
operator-owned allowlist of approved circuit builds keyed by circuit id
and artifact digest. The catalog supplies artifacts, never approval.

## The derivation secret is permanent

```
seed = HKDF-SHA256(secret, info = lp("vc/seed/v1") || lp(seed_bytes)
                                  || lp(context)
                                  || lp(subject_1) || ... || lp(subject_n))
commitment = SHA-256(seed)
```

`lp(x)` is a two-byte big-endian length followed by the bytes, so no two
context fields can be slid into one another, and a field longer than 65535
bytes is refused rather than truncated into a collision.

There is deliberately **no field count** in the info string. It is
unnecessary — length-prefixed fields are self-delimiting, so `["ab","c"]`,
`["a","bc"]` and `["abc"]` already derive three different seeds — and it
is forbidden, because a count would sit before the identifiers and change
what a one-element list derives, moving every seed ever issued.

The file holds the secret **base64url-encoded**, and the decoded value must
be at least 32 bytes — 32 raw bytes in the file decode to 24 or fail
outright. `head -c 32 /dev/urandom | basenc --base64url | tr -d '='`
produces one.

**Back the secret up. Do not rotate it.**

Every commitment this deployment has ever written is a function of that
secret. Replacing it gives every subject a new seed, a new commitment and a
new pseudonym, which breaks every pseudonym a Relying Party already holds.
Losing it destroys the ability to reproduce any seed ever issued over —
there is no copy anywhere else, because nothing is stored.

That is why there is deliberately **no key identifier and no rotation
mechanism**: having one would suggest the secret is a thing you rotate.
Treat it with more care than a signing key, not the same — a signing key
can be replaced after a compromise, and this cannot.

Changing `seed_bytes` has the same effect, and for the same reason: the
length is part of the derivation, not just the output size.

`seed_bytes` is also floored at 16, the default. The seed is the opening
of a commitment that is published in a credential, so a short seed is a
small search space rather than a short key: at one byte there are 256
possible openings and anyone holding the commitment finds the right one,
however long the derivation secret is. The same ceiling bounds how many
subjects can hold distinct seeds, so a short length also hands two people
the same pseudonym.

## Who can link a pseudonym to a person

Whoever holds the secret. That is the design — it is what known-offender
matching and account recovery are built on — and it is also the privacy
cost, so the secret deserves the handling that follows from it: a dedicated
file or secret, restricted to the issuer, backed up somewhere it will
survive the loss of the host.

Note also that every credential of a batch carries the same commitment, and
so does every credential ever issued to that subject. Hidden when a proof
is made over it, but an equality marker for anyone who sees two issued
credentials in the clear — an argument for credential response encryption
on these configurations.

## Remapping a pseudonym

`seed_recover` reproduces a subject's seed, its commitment, and the
pseudonym a Verifier reported, from the same configuration the issuer runs
on:

```
make build-seed-recover

./bin/seed_recover -config /etc/vc/config.yaml -seed primary \
    -subject SE -subject 198001011234 \
    -pseudonym-config known-offender-matching-ssc \
    -verifier-id verifier.example \
    -expect <pseudonym the verifier reported>
```

Repeat `-subject` once per configured path, **in the configured order**:
order is part of the derivation, so the same identifiers given the other
way round reproduce a different seed and the tool will report no match
rather than report an error.

It exits 0 on a match and 2 on a mismatch, so it can drive a loop over
candidate subjects. `-expect` requires `-pseudonym-config`: without one
there is nothing to compare against, and exiting 0 regardless would report
a match for every candidate. The seed itself is printed only with
`-show-seed`.

`-verifier-id` is the **bare** verifier_id — `verifier.example` — not the
prefixed Client Identifier and not `client_id` as it appears in the
request. `verifier_id_type` is agreed out of band between wallet and
verifier and is not hashed. The rulebook states this with worked digests
and marks the prefixed form MUST NOT:

```
SHA256("verifier.example")              = be6a6400…4a41   (MUST)
SHA256("x509_san_dns:verifier.example") = 6eae85a0…6bab   (MUST NOT)
```

A value carrying `x509_san_dns:` is therefore **refused** rather than
stripped. Hashing it would succeed and return a pseudonym no Verifier
could have reported, so the loop would simply never match and the
operator would conclude the subject is innocent — and stripping it would
quietly accept a caller that is confused about which value it holds.

`semantic_id:` is **not** one of those, and must be passed WHOLE. The
rulebook says in those words that it is part of the `semantic`
verifier_id value and not a Client Identifier Prefix, so a semantic
Verifier's verifier_id is the entire string `semantic_id:<identifier>`
and that entire string is what is hashed. Removing the prefix produces a
different pseudonym and the same silent non-match.

It reads the issuer's config and secret, so it has to run where those are.
That is the intended restriction rather than an inconvenience: whoever can
run this can link any pseudonym to a person.

The `nym_auth` pseudonym configurations it implements are
`known-offender-matching-ssc`, `known-offender-matching-psc`,
`account-recovery-ssc` and `user-managed-pseudonym-xsite-ssc`. The rulebook
publishes a vector for the seed/commitment pair and none for a pseudonym,
so the pseudonym construction is implemented from the specification text
and has not been checked against a reference output.

## A commitment the HOLDER computes: `source: holder`

The other direction. The wallet derives `private_seed` — per issuer,
from its account key, the credential type and this issuer's
`credential_issuer` identifier — and sends only
`psc = SHA-256(private_seed)`. The issuer writes that into the
credential and never sees the seed.

```yaml
common:
  credential_metadata:
    nym_auth:
      commitments:
        psc:
          source: holder
          subjects: [issuing_country, personal_administrative_number]
```

No `seed`, because nothing is derived here, and no `deliver`, because
there is no seed to deliver. `subjects` is still required, and is what
the record is keyed by.

**The wire.** The commitment travels as the claim `org.siros.psc` in
the OpenID4VCI **proof JWT**, unpadded base64url of 32 bytes, so the
proof of possession's signature covers it. That does not make the
commitment verifiable — nothing can check it against a seed the issuer
never sees — but it makes the request attributable to the wallet that
made it, which is what gives the rate limit and the audit trail on a
reset something to stand on. A value an attacker could place forces
the subject it names through re-identification to recover.

The issuer advertises the expectation by name:

```json
"credential_metadata": {
  "org.siros.holder_commitments": {"commitments": ["psc"]}
}
```

Names only, as for the seed advertisement, and for the same reason: a
wallet that cannot see the expectation has no reason to put the claim
in its proof.

**One per subject.** The rulebook allows one holder-supplied commitment
per subject per issuer, and this issuer keeps a record of the one it
accepted — keyed by the ordered `subjects`, hashed, never the
identifiers themselves. The same commitment presented again is accepted
(re-issuance, batch issuance and a retried request all reach that
path). A **different** one is refused:

```
HTTP 400  invalid_credential_request
error_description: org.siros.psc_conflict: this subject already has a
  nym_auth commitment on record; a wallet that has lost its account key
  needs an operator-approved reset
```

Refused **before anything is issued** — no credential is signed and no
status-list index is burned. The `org.siros.psc_conflict:` prefix is
there so a wallet SDK can surface this distinguishably: "you need an
operator-approved reset" is a message a user has to see, not a failed
issuance.

Issuing with the recorded commitment instead of refusing would be worse
than refusing. The holder would get a credential committing to a seed
its current wallet cannot open, and would find out at presentation,
with nothing in the failure to suggest why.

**Startup requires**, and refuses without: the commitment store; a
non-empty `subjects`; the claim declared in the credential's type
metadata, as for an issuer-derived one; `proof_types_supported` on the
credential configuration, since the commitment arrives in a proof; and
`doctype` or `vct`, which is the credential type the wallet derives its
seed for.

**Account loss** is a reset, not a new person — see
https://github.com/SUNET/vc/issues/823 for the operator-approved reset
and its audit trail.

## Not implemented yet

- **`model: stored`** — a random seed drawn on first sight of a subject
  and kept, as an alternative to a permanent secret. It needs a
  per-subject store of seeds, which is a different store from the
  commitment record above: that one holds commitments, which are public
  values, and this one would hold secrets.
