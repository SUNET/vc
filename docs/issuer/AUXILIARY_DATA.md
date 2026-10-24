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
`hash_commitment` on a claim the credential's type metadata declares:

- in an `mso_mdoc` credential, a `bstr` element of the MDDL, at its
  namespace and element;
- in an SD-JWT VC, a claim of the VCTM with `sd: always`, so the holder can
  withhold it, carrying the commitment base64url-encoded at its claims
  path. The path stays clear of the claims the SD-JWT builder writes
  (`iss`, `vct`, `cnf`, `status`, …), and the VCTM declares nothing beneath
  it.

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

Every data source scope that serves the credential fulfils each `to_wallet`
entry with one `hash_commitment` derivation, which names the entry by its
`path` and says how the opening is produced. Here `nym_auth` is issued from
a presented SD-JWT or mdoc PID:

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

## Openings

`opening` sets one of:

- `hkdf` derives the opening from a secret and the ordered `inputs`.
- `random` draws random bytes.

Both take `bytes`, the opening length the credential type defines, from 16
to 64.

```
opening = HKDF-SHA256(secret, info = lp("vc/seed/v1") || lp(bytes)
                                     || lp("")
                                     || lp(input_1) || ... || lp(input_n),
                      length = bytes)
commitment = SHA-256(opening)
```

`lp(x)` is a two-byte big-endian length followed by the bytes. Each input
is a non-empty string claim of the source data.

The secret file holds the secret **base64url-encoded**, decoding to at
least 32 bytes. `head -c 32 /dev/urandom | basenc --base64url | tr -d '='`
produces one. `create_pki.sh` writes one to `developer_tools/pki`, and the
Fly deploy provisions one per environment as the `NYM_AUTH_SEED` secret.

**Back the secret up, and keep it.** Every opening this deployment issues
is a function of it. A new secret gives every subject a new opening and a
new commitment, and the lost secret takes the ability to reproduce any
earlier opening with it.

## Who can reproduce an opening

Whoever holds the secret reproduces the opening of any subject from its
identifiers. The secret belongs in a dedicated file or secret, restricted
to the issuer, and backed up where it survives the loss of the host.

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

`-input` takes the values of the `hkdf` inputs, **in the configured order**,
as the source data carried them. `-path` names the entry as a JSON claims
path, such as `["eu.europa.ec.eudi.nym_auth.1","ssc"]`, and can be left out
when the credential has one `hkdf` entry. The tool prints the commitment of
each source scope, and the opening only with `-show-opening`. With
`-expect` it exits 0 on a match and 2 on a mismatch, so it can drive a loop
over candidates.

It reads the secret the opening names, so it runs where the secret is.
