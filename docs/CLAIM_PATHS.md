# Claims path pointers

Every field that names a claim of a credential takes a claims path pointer
(OpenID4VP 1.0 section 7). A pointer is an array. Each element selects
within what the elements before it selected:

- A string selects the member of an object with that name.
- `null` selects every element of an array.
- A non-negative integer selects the element of an array at that index.

An mdoc claim is `[namespace, element]`, such as
`[org.iso.18013.5.1, given_name]` (section 7.2).

```yaml
- path: [given_name]
- path: [address, locality]
- path: [nationalities, null]
- path: [nationalities, 0]
- path: [eu.europa.ec.eudi.pid.1, birth_date]
```

## Fields

| Field | Form |
| --- | --- |
| `common.credential_metadata.*.auxiliary_data.{to_wallet,to_issuer}[].path` | pointer |
| `apigw.auth_providers.{oidc,saml}.attribute_mapping.*.claim` | pointer into the claims the mapping writes |
| `apigw.data_sources.external_api.scopes.*.attribute_mapping.*.claim` | pointer into the scope's credential document |
| `apigw.data_sources.datastore.scopes.*.auth_scopes.*.auth_claims` | list of pointers into the presented credential |
| `apigw.data_sources.datastore.scopes.*.auth_scopes.*.identity_attributes` | list of `{path, attribute}` |
| `apigw.data_sources.datastore.scopes.*.auth_scopes.*.document_claims` | list of `{from, to}`: `from` points into the presented credential, `to` at a top-level claim of the issued document |
| `apigw.data_sources.presentation.scopes.*.from.*.required_claims` | list of `{path, values}`; without `values`, any value passes |
| `apigw.data_sources.{assertion,presentation}.scopes.*.defaults` | list of `{path, value}` |
| `input` and `output` of each derivation primitive | pointer |
| `hash_commitment.path`, the `inputs` of an `hkdf` or `hmac` opening, the `input` of a `claim` opening | pointer, list of pointers |
| `verifier.presets.*.credentials.*.{claims,exclude_claims,validations}[].path` | pointer |
| `verifier.combined_presentation.binding_attributes[].paths` | list of pointers, each selecting one claim of the verified claims of every credential |
| `dcql.credentials[].claims[].path` of a presentation request template | pointer |
| `claim_mappings` of a presentation request template | see below |
| `identity_match.claims` of `POST /api/v1/issuance/prepare` | list of `{path, equals}` |

`docs/CONFIGURATION.md` lists each field with an example.

`apigw.data_sources.datastore.scopes.*.auth_claims` names identity fields
of the datastore, and `issuance_policy.query_template[].claim` names OIDC
claims. Both take strings.

## `claim_mappings`

A presentation request template maps the claims of the presented
credentials to OIDC claims in one of two forms.

`"*"` maps every claim of every presentation under its own name:

```yaml
claim_mappings: "*"
```

A map from DCQL credential query id to a list of `{path, claim}` entries
maps each presentation of the `vp_token` through the entries of the query
it answers. Each path points into a presentation in the query's format:

```yaml
dcql:
  credentials:
    - id: pid_sd_jwt
      format: dc+sd-jwt
      meta: {vct_values: ["urn:eudi:pid:1"]}
      claims:
        - path: [given_name]
    - id: pid_mdoc
      format: mso_mdoc
      meta: {doctype_value: eu.europa.ec.eudi.pid.1}
      claims:
        - path: [eu.europa.ec.eudi.pid.1, given_name]
  credential_sets:
    - options: [[pid_sd_jwt], [pid_mdoc]]
claim_mappings:
  pid_sd_jwt:
    - {path: [given_name], claim: given_name}
  pid_mdoc:
    - {path: [eu.europa.ec.eudi.pid.1, given_name], claim: given_name}
```

- A claim the presentation does not carry is left out.
- Two presentations that give one OIDC claim different values are refused.
- Loading refuses a key that names no credential query of the template.

## `identity_match` of `POST /api/v1/issuance/prepare`

`identity_match.claims` lists the claims of the presented credential that
must match, each a pointer and an exact value:

```json
{
  "scope": "pid",
  "identity_match": {
    "claims": [
      {"path": ["family_name"], "equals": "Doe"},
      {"path": ["eu.europa.ec.eudi.pid.1", "birth_date"], "equals": "1990-01-01"}
    ]
  }
}
```

A malformed pointer is answered with `400` and `invalid_claims_path`.

## Deprecated spellings

The earlier release's spellings load with their meaning. Each one logs a
warning at load that names the file, the line, the YAML path, the spelling
and its replacement:

```text
config.yaml:37: $.apigw.data_sources.presentation.scopes.nym_auth.from.pid.required_claims.birthdate: deprecated claim spelling birthdate: []; write {path: [birthdate]}, or run migrate_claim_paths
```

A spelling that a YAML alias or merge key reads warns once per read, at
the line that holds it.

A later release refuses them. Rewrite each file with `migrate_claim_paths`
before then.

| Field | Deprecated spelling | Current spelling |
| --- | --- | --- |
| a claim in any field above | `birthdate`, `address.locality` | `[birthdate]`, `[address, locality]` |
| `required_claims` | `{birthdate: [], assurance_level: [al2]}` | `[{path: [birthdate]}, {path: [assurance_level], values: [al2]}]` |
| `defaults` | `{issuing_country: SE}` | `[{path: [issuing_country], value: SE}]` |
| `identity_attributes` | `{birthdate: birth_date}` | `[{path: [birthdate], attribute: birth_date}]` |
| `document_claims` | `{birthdate: birth_date}` | `[{from: [birthdate], to: [birth_date]}]` |
| a preset path | `[nationalities, "null"]` | `[nationalities, null]` |
| `claim_mappings` | `{"*": "*"}` | `"*"` |
| `claim_mappings` | `{given_name: given_name}` | `{<query id>: [{path: [given_name], claim: given_name}]}` |
| `identity_match.claims` | `{"family_name": {"equals": "Doe"}}` | `[{"path": ["family_name"], "equals": "Doe"}]` |

A dotted name reads as the role that holds it read it:

| Role | JSON-based credential | mdoc |
| --- | --- | --- |
| A claim of a presented credential: auth scope `auth_claims`, the keys of `identity_attributes`, `document_claims` and `required_claims`, a derivation input of a presentation source, `identity_match` | one key per dot-separated segment | `[namespace, element]`, split at the last dot; a name without a dot is an element of `org.iso.18013.5.1` |
| A claim of the issued document: the values of `document_claims`, the keys of `defaults`, derivation outputs, the derivation inputs of the other sources, an external API `attribute_mapping` | one key per segment | one key per segment; a first segment the MDDL declares as an element gains its namespace, the first in sorted order |
| A derivation input that an earlier derivation of the list writes, or a claim beneath one | a claim of the issued document | a claim of the issued document |
| The `input` of `age_over_thresholds`, `yyyymmdd_to_iso` and `swamid_highest_assurance_level`, the `output` of the latter two, and the input of another derivation when an earlier derivation of the list writes the whole name as one key | one key: the whole name | in a presented credential, as above; in document data, one key, which gains its namespace when the MDDL declares it as an element |
| An auth provider's `attribute_mapping` | one key per segment | |
| A verifier `binding_attributes` path | one key per segment | one key per segment |

An earlier `claim_mappings` map merges the claims of all presentations,
a later presentation's claim replacing an earlier one, and reads each name
as one key per dot-separated segment. A presented mdoc carries each element
of `org.iso.18013.5.1` under its bare identifier too.

`POST /api/v1/issuance/prepare` with the deprecated `identity_match` object
answers with the header `Deprecation: @1793836800` (RFC 9745) and logs a
warning.

### `migrate_claim_paths`

`migrate_claim_paths` rewrites configuration files and presentation request
files in place. It keeps every comment, and a second run changes nothing:

```sh
make build-migrate-claim-paths
./bin/migrate_claim_paths -schemas /metadata=./metadata config.yaml presentation_requests/*.yaml
```

- `-schemas PREFIX=DIR` maps a schema path prefix of the configuration to a
  local directory. The converter reads the MDDL of an mdoc credential to
  place a dotted name of its document. Repeat it for several prefixes.
- `-n` reports the rewrites and writes no file.

It prints a line per rewritten file. It converts an earlier `claim_mappings`
map to the keyed form when the keyed form maps the same claims:

- The template has one credential query, and the query allows one
  presentation.
- The query is a mapping with a non-empty `id`. YAML reads its `id` and
  `format` as strings and its `multiple` as a boolean, each written as a
  plain or quoted scalar.
- Each name maps to a distinct, non-empty OIDC claim.
- Each name is a dotted name of non-empty segments. In an mdoc query, it is
  the bare identifier of an element of `org.iso.18013.5.1`.

It leaves any other map as written and prints why. Such a map keeps loading
with its warning.

It leaves a file with a YAML alias, merge key or repeated key as written,
and prints a line, when an alias stands where it reads claims, or when a
rewrite in place would change what the file loads. Rewrite by hand the
spellings its warnings at load name.
