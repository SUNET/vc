# Credential Auxiliary Data

A credential configuration can exchange Credential Auxiliary Data
(`openid-4-verifiable-credential-issuance-auxiliary-data.md` in
sirosfoundation/nym_auth_rulebook) with the wallet:

- a `to_wallet` `hash_commitment` puts SHA-256 of an opening into the
  credential and sends the opening to the wallet in the encrypted
  Credential Response;
- a `to_issuer` `hash_commitment` puts the commitment the wallet sends in
  its key proofs into the credential.

The EUDI `nym_auth` attestation uses both: `ssc` commits to an opening the
issuer derives, `psc` to a secret the wallet holds.

## Configuration

`credential_metadata.<scope>.auxiliary_data` is published as the
configuration's `auxiliary_data_supported`. Each entry is a sha-256
`hash_commitment` on a `bstr` element of the credential's MDDL. A
`to_issuer` entry is `required` when its MDDL element is mandatory:

```yaml
common:
  credential_metadata:
    nym_auth:
      mddl_file_path: /metadata/nym_auth.mdoc.json
      format: mso_mdoc
      auxiliary_data:
        to_wallet:
          - {type: hash_commitment, alg: sha-256, path: [eu.europa.ec.eudi.nym_auth.1, ssc]}
        to_issuer:
          - {type: hash_commitment, alg: sha-256, path: [eu.europa.ec.eudi.nym_auth.1, psc]}
```

A `hash_commitment` derivation configures an entry in a data source scope
that serves the credential, and names it by its `path`. Every source scope
configures each `to_wallet` entry with an `opening`, which says how the
issuer produces it. The wallet holds the opening of a `to_issuer` entry.
Here `nym_auth` is issued from a presented SD-JWT or mdoc PID:

```yaml
apigw:
  data_sources:
    presentation:
      scopes:
        nym_auth:
          from:
            pid:
              required_claims:
                birthdate: []
                issuing_country: []
                personal_administrative_number: []
              derivations:
                - copy: {input: birthdate, output: birth_date}
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, ssc]
                    opening:
                      hkdf:
                        secret_path: /pki/nym_auth_seed.key
                        inputs: [issuing_country, personal_administrative_number]
            pid_mdoc:
              required_claims:
                eu.europa.ec.eudi.pid.1.birth_date: []
                eu.europa.ec.eudi.pid.1.issuing_country: []
                eu.europa.ec.eudi.pid.1.administrative_number: []
              derivations:
                - copy: {input: eu.europa.ec.eudi.pid.1.birth_date, output: birth_date}
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, ssc]
                    opening:
                      hkdf:
                        secret_path: /pki/nym_auth_seed.key
                        inputs: [eu.europa.ec.eudi.pid.1.issuing_country, eu.europa.ec.eudi.pid.1.administrative_number]
```

A `hash_commitment` derivation reads the claims of the source data: the
verified presented claims for a presentation scope, the document data for
the others.

The issuer requires `credential_response_encryption` on a request for a
credential with `to_wallet` entries, and
`apigw.issuer_metadata.credential_encryption.keys` to offer it.

## Entries from the wallet

The issuer reads the wallet's entries from its verified `jwt` and
`attestation` key proofs. In BBS flows they belong in the `di_vp` key
proof, where `auxiliary_data` is a property of the Verifiable Presentation
(section 6.2 of the extension).

## Unique commitments

`unique` makes the issuer accept one commitment per value of a key, in
either direction. `key` lists claims of the credential:

- `key: []` accepts one commitment for the entry;
- one claim accepts one commitment per value of that claim;
- several claims accept one commitment per combination of their values.

The issuer keeps the first commitment for each key value, and answers a
different one with `auxiliary_data_conflict`. The nym_auth rulebook allows
one `psc` per subject, and `ssc` identifies the subject, so each source
scope of `nym_auth` adds:

```yaml
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, psc]
                    unique:
                      key:
                        - [eu.europa.ec.eudi.nym_auth.1, ssc]
```

The record lives in the apigw database (`unique_commitments`), which
decides between replicas. It holds the SHA-256 of the key and its values.
Each key of an entry has its own records.

### Resetting a commitment

A wallet that lost its account key sends a new commitment, which the issuer
refuses. Once the person is re-identified, an operator resets the recorded
commitment, and the next issuance records the new one.

In the admin UI, **Unique Commitments** lists the unique entries and the
values each key needs. Through the API:

```
POST /api/v1/auxiliary_data/reset
{
  "scope": "nym_auth",
  "path": ["eu.europa.ec.eudi.nym_auth.1", "psc"],
  "key": [
    {"path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"], "inputs": ["SE", "pan-200"]}
  ],
  "evidence_ref": "case-1234"
}
```

`key` names each key part by its `path`, in the configured order. A part
takes the `value` the credential carries, as text. A part that is a
`to_wallet` entry with an `hkdf` opening also takes the `inputs` it derives
from, in the configured order. `evidence_ref` references the
re-identification record. The reset is stored with it, and one reference
resets one commitment.

| Answer | Meaning |
| --- | --- |
| 204 | The commitment is reset. |
| 400 | The scope has no unique entry with this path and key, or a part has no value, or its inputs fit no `hkdf` opening. |
| 403 | The caller is anonymous: a reset needs an API token or an OIDC admin session. |
| 404 | Nothing is on record for this key value. |
| 409 | The evidence reference already reset an earlier commitment. |

Each call is logged with the scope, the entry, the operator, the evidence
reference and the outcome. Each reset adds a row to
`unique_commitment_resets` with the operator, the time, the evidence
reference and the SHA-256 of the removed commitment.

The reset is an admin API route. Where `apigw.api_server.api_auth.rules`
are set, an operator needs a rule such as:

```
(vc (service apigw)(method POST)(path /api/v1/auxiliary_data/reset)(subject <operator>)(authentic_source *)(scope nym_auth))
```

Resets need `apigw.api_server.api_auth`; the apigw warns at startup for
each unique entry when it is absent.

## Openings

`opening` sets one of:

- `hkdf` derives the opening from a secret and the ordered `inputs`.
- `random` draws `bytes` random bytes (default 16).

```
opening = HKDF-SHA256(secret, info = lp("vc/seed/v1") || lp(16)
                                     || lp("")
                                     || lp(input_1) || ... || lp(input_n))
commitment = SHA-256(opening)
```

`lp(x)` is a two-byte big-endian length followed by the bytes. Each input
is a non-empty string claim of the source data.

The secret file holds the secret **base64url-encoded**, decoding to at
least 32 bytes. `head -c 32 /dev/urandom | basenc --base64url | tr -d '='`
produces one. `create_pki.sh` writes one to `developer_tools/pki`, and the
Fly deploy provisions one per environment as the `NYM_AUTH_SEED` secret.

**Back the secret up, and keep it.** Every opening this deployment issues
is a function of it. A new secret gives every person a new opening, a new
commitment and new pseudonyms, and the lost secret takes the ability to
reproduce any earlier opening with it.

## Who can link a pseudonym to a person

Whoever holds the secret. Known-offender matching and account recovery are
built on that, and it is also the privacy cost: the secret belongs in a
dedicated file or secret, restricted to the issuer, and backed up where it
survives the loss of the host.

Every credential issued to a person carries the same commitment. It stays
hidden when a proof is made over it, and it is an equality marker for
anyone who sees two issued credentials in the clear.

## Remapping a pseudonym

`seed_recover` reproduces a person's opening, its commitment, and the
pseudonym a Verifier reported, from the secret of the `hkdf` opening:

```
make build-seed-recover

./bin/seed_recover -secret-path /pki/nym_auth_seed.key \
    -subject SE -subject pan-100 \
    -pseudonym-config known-offender-matching-ssc \
    -verifier-id verifier.example \
    -expect <pseudonym the verifier reported>
```

Repeat `-subject` once per `hkdf` input, **in the configured order**, with
the value the source data carried.

It exits 0 on a match and 2 on a mismatch, so it can drive a loop over
candidates. `-expect` requires `-pseudonym-config`. The opening itself is
printed only with `-show-seed`.

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
stripped. Hashing it would succeed and return a pseudonym no Verifier could
have reported, so the loop would simply never match and the operator would
conclude the subject is innocent — and stripping it would quietly accept a
caller that is confused about which value it holds.

**`semantic_id:` is not the same kind of thing, and must NOT be stripped.**
It looks like a Client Identifier Prefix and is not one: for a semantic
Verifier the verifier_id *is* the whole string `semantic_id:<identifier>`,
and that whole string is what is hashed. Pass it exactly as the Verifier
publishes it.

```
-verifier-id verifier.example                 # x509_san_dns Verifier: bare, no prefix
-verifier-id semantic_id:age-over-18-check    # semantic Verifier: the marker is part of the value
```

So the rule is not "strip anything before a colon". It is: a Client
Identifier Prefix is never hashed, and a semantic identifier always is.
Getting this backwards fails the same silent way as the prefixed form —
a pseudonym no Verifier reports, a loop that never matches, and a subject
who looks innocent. The one case refused is a bare `semantic_id:` with
nothing after it, which names no Verifier at all.

It reads the issuer's secret, so it runs where the secret is. Whoever can
run it can link any pseudonym to a person.

The `nym_auth` pseudonym configurations it implements are
`known-offender-matching-ssc`, `known-offender-matching-psc`,
`account-recovery-ssc` and `user-managed-pseudonym-xsite-ssc`. The rulebook
publishes a vector for the seed/commitment pair and none for a pseudonym,
so the pseudonym construction is implemented from the specification text
and has not been checked against a reference output.
