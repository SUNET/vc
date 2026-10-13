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

- **It does not deliver the seed.** What reaches a wallet is the
  commitment, as a claim. There is no response member and no endpoint for
  the seed, and there is not going to be one: a derived seed is
  recomputable whenever it is wanted, so there is no moment at which it
  must be handed over to avoid losing it. A credential is consequently not
  usable in a proof that needs the seed until the seed reaches the holder
  by some route defined elsewhere.
- **It does not keep the commitment from being disclosed.** A commitment
  claim is an ordinary selectively-disclosable element, and a Verifier is
  free to ask for it. Whether it is ever answered is enforced by the
  wallet, against whatever rulebook governs the credential. A control here
  could not stop a Verifier that asks; it could only create the belief
  that something was stopping it.
- **It does not check a consumer's issuance profile.** Whether the result
  satisfies some circuit's byte-level expectations is between that
  consumer's specification and its rulebook.

## Configuration

Two blocks. A seed source on the issuer:

```yaml
issuer:
  seeds:
    primary:
      model: derived
      secret_path: /etc/vc/seed/issuer.key   # >= 32 bytes, base64url
      # secret: <base64url>                  # the inline alternative; not both
      # seed_bytes: 16                       # default
```

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
          subject: personal_administrative_number
          # commit: sha-256     # default, and the only registered function
          # context: ""         # default; see below before setting one
          # encoding: base64    # default by format; see below
```

A credential with no `commitments` block is issued exactly as it is today.

### `subject` — what "the same person" means

`subject` is a path into the document data the issuer receives, naming the
stable identifier the seed is derived from. It is the **one** input that
separates one person's seed from another's, so what it points at decides
what "the same person" means for every pseudonym built on this credential.
A deployment issuing a Swedish PID might point it at the personnummer.

For `mso_mdoc` the document data is flat and keyed by element identifier,
so the path is the element identifier — including one containing dots,
which is read as a single key and not as a descent. For every other format
a dotted path descends into the JSON object.

`subject` is read from the document data **as received**, before any
commitment is written into it. A `subject` naming another commitment's
claim path therefore refuses rather than deriving a seed from a value this
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
**refuses the issuance**. There is no fallback: deriving over `""` would
give every subject whose identity failed to resolve the same seed, and so
the same pseudonym — which is exactly the failure the identifier exists to
prevent, arriving silently.

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

## The derivation secret is permanent

```
seed = HKDF-SHA256(secret, info = lp("vc/seed/v1") || lp(seed_bytes)
                                  || lp(context) || lp(subject))
commitment = SHA-256(seed)
```

`lp(x)` is a two-byte big-endian length followed by the bytes, so no two
context fields can be slid into one another.

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
    -subject 198001011234 \
    -pseudonym-config known-offender-matching-ssc \
    -verifier-id x509_san_dns:rp.example \
    -expect <pseudonym the verifier reported>
```

It exits 0 on a match and 2 on a mismatch, so it can drive a loop over
candidate subjects. `-expect` requires `-pseudonym-config`: without one
there is nothing to compare against, and exiting 0 regardless would report
a match for every candidate. The seed itself is printed only with
`-show-seed`.

It reads the issuer's config and secret, so it has to run where those are.
That is the intended restriction rather than an inconvenience: whoever can
run this can link any pseudonym to a person.

The `nym_auth` pseudonym configurations it implements are
`known-offender-matching-ssc`, `known-offender-matching-psc`,
`account-recovery-ssc` and `user-managed-pseudonym-xsite-ssc`. The rulebook
publishes a vector for the seed/commitment pair and none for a pseudonym,
so the pseudonym construction is implemented from the specification text
and has not been checked against a reference output.

## Not implemented yet

Both need a per-subject store, which the issuer does not have. A
configuration asking for either is refused at startup rather than ignored:

- **`model: stored`** — a random seed drawn on first sight of a subject and
  kept, as an alternative to a permanent secret.
- **`source: holder`** — a commitment the wallet computes over a seed the
  issuer never sees (`psc`). The `nym_auth` rulebook requires an issuer to
  allow only one such commitment per subject, and enforcing that needs a
  record of the one it accepted.
