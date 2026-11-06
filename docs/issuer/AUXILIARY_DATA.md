# Credential Auxiliary Data

A credential configuration can exchange Credential Auxiliary Data
(`openid-4-verifiable-credential-issuance-auxiliary-data.md` in
sirosfoundation/nym_auth_rulebook) with the wallet:

- a `to_wallet` `hash_commitment` puts SHA-256 of an opening into the
  credential and sends the opening to the wallet in the encrypted
  Credential Response;
- a `to_issuer` `hash_commitment` puts the commitment the wallet sends in
  its key proofs into the credential.

The examples configure the EUDI `nym_auth` attestation, which uses both:
`ssc` commits to an opening the issuer derives, `psc` to a secret the
wallet holds.

## Configuration

`credential_metadata.<scope>.auxiliary_data` is published as the
configuration's `auxiliary_data_supported`. Each entry is a sha-256
`hash_commitment` on a claim the credential's type metadata declares.
`encoding` sets how the claim represents the commitment: `base64url`
(without padding), `base64` or `hex` text, or the bytes when absent. The
claim is:

- in an `mso_mdoc` credential, an element of the MDDL at its namespace and
  element: a `bstr` for the bytes, a `tstr` for text;
- in an SD-JWT VC, a claim of the VCTM with `sd: always`, so the holder can
  withhold it, and the entry sets an encoding. The path stays clear of the
  claims the SD-JWT builder writes (`iss`, `vct`, `cnf`, `status`, …), and
  the VCTM declares nothing beneath it.

A `to_issuer` entry is `required` when its claim is mandatory:

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
                        bytes: 16
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
                        bytes: 16
```

A `hash_commitment` derivation reads the claims of the source data: the
verified presented claims for a presentation scope, and for the others the
claims the source supplied before any derivation or document filter ran. A
presentation verifies its `required_claims` alone, so each claim an opening
reads is a key of `required_claims`.

The issuer requires `credential_response_encryption` on a request for a
credential with `to_wallet` entries, and
`apigw.issuer_metadata.credential_encryption.keys` to offer it.

## Entries from the wallet

The issuer reads the wallet's entries from its verified `jwt` and
`attestation` key proofs. In BBS flows they belong in the `di_vp` key
proof, where `auxiliary_data` is a property of the Verifiable Presentation
(section 6.2 of the extension).

A credential carries a `to_issuer` commitment only when the wallet sent
it. For an optional entry the wallet leaves out, the issuer removes any
value the source data holds at its path.

## Unique commitments

`unique` makes the issuer accept one commitment per value of a key, in
either direction. `key` lists claims of the credential:

- `key: []` accepts one commitment for the entry;
- one claim accepts one commitment per value of that claim;
- several claims accept one commitment per combination of their values.

A key claim cannot be:

- the entry, or an object or array that holds it, since every commitment
  changes it;
- a `to_issuer` entry whose claim the type metadata leaves optional;
- in an SD-JWT VC, a claim the credential builder writes itself.

The issuer records the first commitment for each key value, once the
request has passed its checks and before it signs the credential. A
different commitment for a recorded key value refuses the request:

- on a `to_issuer` entry, whose commitment the wallet sent, with
  `auxiliary_data_conflict`;
- on a `to_wallet` entry, whose commitment the issuer derived, with
  `credential_request_denied`.

A refused request leaves no record: of a credential's unique entries, the
issuer records all or none.

With a `random` opening each issuance draws a new commitment, so a unique
`to_wallet` entry issues once per key value until a reset.

The nym_auth rulebook allows one `psc` per subject, and `ssc` identifies
the subject, so each source scope of `nym_auth` adds:

```yaml
                - hash_commitment:
                    path: [eu.europa.ec.eudi.nym_auth.1, psc]
                    unique:
                      key:
                        - [eu.europa.ec.eudi.nym_auth.1, ssc]
```

Every source scope of a credential sets the same unique entries, with the
same key, and the configuration is refused otherwise.

The record lives in the apigw database (`unique_commitments`), which
decides between replicas. It holds the SHA-256 of the key and its values.
Each key of an entry has its own records.

The shipped configs key the `psc` record by the issued `ssc`, which
derives from the `hkdf` secret, `nym_auth_seed.key` (`NYM_AUTH_SEED` on
Fly). Replacing the secret changes every subject's `ssc`, orphans every
record, and lets every subject register a new `psc`.

### Finding and resetting a commitment

An operator resets the commitment on record for a key value, and the next
issuance records a new one. For `nym_auth`, that is a person who lost
their wallet account and was re-identified.

In the admin UI, **Commitments** finds the commitment for the values an
operator enters, shows when it was recorded, and resets it with a case
reference. Reset needs an operator signed in through
`apigw.api_server.api_auth.oidc`. Through the API, both calls take the
entry and a value per key part:

```
POST /api/v1/auxiliary_data/lookup
{
  "scope": "nym_auth",
  "path": ["eu.europa.ec.eudi.nym_auth.1", "psc"],
  "key": [
    {"path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"], "inputs": ["SE", "pan-200"]}
  ]
}

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
takes the `value` the credential carries, as text, and a claim that holds
bytes takes them in base64. A part that is a
`to_wallet` entry with an `hkdf` or `hmac` opening also takes the `inputs`
it derives from, in the configured order. `evidence_ref` references the operator's
case record. The reset is stored with it, and one reference resets one
commitment.

The lookup answers 200 with `recorded_at`, or 404 when nothing is on
record. The reset answers:

| Answer | Meaning |
| --- | --- |
| 204 | The commitment is reset. |
| 400 | The scope has no unique entry with this path and key, or a part has no value, or its inputs fit no `hkdf` or `hmac` opening. |
| 403 | The caller is anonymous: a reset needs an API token or an OIDC admin session. |
| 404 | Nothing is on record for this key value, or a concurrent reset removed it first. |
| 409 | The evidence reference already reset an earlier commitment. |

Each call is logged with the scope, the entry, the operator and the
outcome, and a reset with its evidence reference. A reset adds a row to
`unique_commitment_resets` with the operator, the time, the evidence
reference and the SHA-256 of the commitment, and then removes the
commitment. The row stays: the table holds every approval, including one a
concurrent reset beat, which answered 404. A retry with the same reference
completes a reset interrupted between the two steps.

Both are admin API routes. Where `apigw.api_server.api_auth.rules` are
set, an operator needs a rule such as:

```
(vc (service apigw)(method POST)(path /api/v1/auxiliary_data/*)(subject <operator>)(authentic_source *)(scope nym_auth))
```

Resets need `apigw.api_server.api_auth`; the apigw warns at startup for
each unique entry when it is absent.

## Openings

`opening` sets one of:

- `hkdf` derives the opening from a secret and the ordered `inputs`, in 16
  to 64 `bytes`.
- `hmac` derives it from the same configuration, in 16 to 32 `bytes`.
- `claim` takes the opening from a claim of the source data.
- `random` draws 16 to 64 random `bytes`.

`bytes` is the opening length the credential type defines. The commitment
is `SHA-256(opening)`.

### `hkdf` and `hmac`

```
message = lp(label) || lp(bytes) || lp(input_1) || ... || lp(input_n)

hkdf: opening = HKDF-SHA256(secret, salt = empty, info = message, length = bytes)
hmac: opening = HMAC-SHA256(secret, message), truncated to bytes
```

`label` is `vc/hash_commitment/hkdf/v1` for `hkdf` and
`vc/hash_commitment/hmac/v1` for `hmac`. `lp(x)` is a two-byte big-endian
length followed by the bytes, and `bytes` is written in decimal. Each input
is a non-empty string claim of the source data.

Pick `hmac` when the opening must also be computed where only HMAC is
available, such as a PKCS#11 HSM without HKDF, and `hkdf` otherwise. An
`hmac` opening is the HMAC output truncated to at least half its 32 bytes
(RFC 2104 section 5). The labels differ, so moving an entry from one to the
other gives every subject a new opening and a new commitment.

The secret file holds the secret **base64url-encoded**, decoding to at
least 32 bytes, and only its owner can read it.
`(umask 077; head -c 32 /dev/urandom | basenc --base64url | tr -d '=' > nym_auth_seed.key)`
writes one. `create_pki.sh` writes one to `developer_tools/pki`, and the
Fly deploy provisions one per environment as the `NYM_AUTH_SEED` secret.

**Back the secret up, and keep it.** Every opening this deployment issues
is a function of it. A new secret gives every subject a new opening and a
new commitment, and the lost secret takes the ability to reproduce any
earlier opening with it. Records keyed by such a commitment are orphaned
too ([Unique commitments](#unique-commitments)).

### `claim`

`claim` names the claim of the source data, `input`, that holds a
per-subject secret as base64url text decoding to 16 to 64 bytes. The opening
is those bytes. Pick it when the authentic source already stores such a
secret for each subject, so the issuer holds no secret of its own:

```yaml
- hash_commitment:
    path: [eu.europa.ec.eudi.nym_auth.1, ssc]
    opening:
      claim: {input: nym_auth_opening}
```

The extension requires at least 128 bits of entropy in an opening (section
4.1). A low-entropy claim, such as a date of birth or a personal number, can
only be an `hkdf` or `hmac` input, and never an opening. The length rule
refuses a date of birth: `1990-01-01` decodes to 7 bytes. A value that is
absent, not a string, not base64url or out of range fails issuance, and the
error names the claim only.

The claim is a secret. The configuration is refused when the credential
carries the claim, or when another derivation reads it. An mdoc carries
each document key its MDDL declares as an element, and an SD-JWT VC from a
presentation each claim its VCTM declares. An SD-JWT VC from the
datastore, an assertion or an external API carries its whole document, so
there `claim` serves an mdoc only.

## Who can reproduce an opening

Whoever holds the secret of an `hkdf` or `hmac` opening reproduces the
opening of any subject from its identifiers. The secret belongs in a
dedicated file or secret, restricted to the issuer, and backed up where it
survives the loss of the host. Whoever reads the source's claim reads a
`claim` opening.

Every credential issued to a subject carries the same commitment. It stays
hidden when a proof is made over it, and it is an equality marker for
anyone who sees two issued credentials in the clear.

## Reproducing an opening

`opening_recover` reproduces the opening of a `to_wallet` entry, and its
commitment, from the issuer's config file and a subject's identifiers:

```
make build-opening-recover

./bin/opening_recover -config /config.yaml -scope nym_auth \
    -input SE -input pan-100 \
    -expect <commitment in hex>
```

`-input` takes the values of the `hkdf` or `hmac` inputs, **in the
configured order**, as the source data carried them. `-path` names the
entry as a JSON claims path, such as `["eu.europa.ec.eudi.nym_auth.1","ssc"]`,
and can be left out when the credential has one `to_wallet` entry. The tool
prints the commitment of each source scope, and the opening only with
`-show-opening`. With `-expect` it exits 0 on a match and 2 on a mismatch,
so it can drive a loop over candidates.

A `claim` or `random` opening has nothing to derive, and the tool prints the
reason in place of a commitment: a `claim` opening is read from the source,
at the claim it names. An entry without an `hkdf` or `hmac` opening is an
error.

It reads the secret the opening names, so it runs where the secret is.
