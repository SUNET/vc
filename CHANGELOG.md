# Changelog

## [Unreleased]

### Breaking Changes

- **Data Integrity proofs now secure the document they are attached to.**
  All three cryptosuites — `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and
  `ecdsa-sd-2023` — used to remove EVERY proof in the graph when
  canonicalizing, where the specification removes only the proof being
  created or verified. A presentation's signature therefore did not
  cover the issuer proof of the credential it carried, so that proof could be
  stripped or swapped with the presentation still verifying. Only the root's
  own proofs are removed now, and an embedded credential's proof is part of
  the document the presentation secures.

  The proof to verify is also read off the document rather than searched for
  or inferred from the RDF reference graph: `Sign` attaches its proof to the
  top-level node, so a proof found anywhere else is not the document's own. A
  proof moved onto an embedded credential no longer verifies.

  **Migration:** a presentation signed before this release stops verifying if
  it CARRIES a proof that is not its own — an embedded credential's issuer
  proof, which is the case this change exists to secure. Those must be
  re-presented, under both RDF cryptosuites. A presentation with nothing
  embedded has the same unsecured RDF under the old removal and the new one
  and verifies unchanged.

  Most credentials are unaffected: a credential that carries no proof but its
  own makes the two removals the same operation.

  **A credential that NESTS a secured credential is affected under ALL THREE
  cryptosuites** — under `credentialSubject`, `evidence` or `@included`. Every
  suite used to remove that nested proof when canonicalizing, leaving it
  outside the signed quad set entirely, so it could be stripped or re-pointed
  at another key with the signature still verifying. It is now part of the
  document the signature covers, which means a proof made over such a
  credential before this release no longer verifies — `eddsa-rdfc-2022` and
  `ecdsa-rdfc-2019` as much as `ecdsa-sd-2023`. Re-issue those credentials.
  For `ecdsa-sd-2023` a derived proof made from such a base proof no longer
  checks out either.

  **`ecdsa-sd-2023` derived credentials are affected more widely than that.**
  Deriving used to compact the flattened dataset and attach the derived proof
  to the bare `@graph` container it came back as — a document about nothing,
  whose proof the old verifier found by walking the graph. The root-scoped
  verifier reads a document's proofs off its root, and a container has none,
  so **every previously issued derived credential that came out as a
  multi-node `@graph` container stops verifying**. In practice that is any
  derivation from a credential with nested nodes — a `credentialSubject`
  holding an object rather than a bare identifier, say. Derivations that
  compacted down to a single node are unaffected. Re-derive from the base
  credential; the base proof itself is unchanged unless the credential nests a
  secured credential, as above.

  Two derivations are now refused outright rather than producing a document
  that cannot be verified: one whose disclosure drops every triple of the
  credential node (what is left is a document about the subject, carrying the
  credential's proof), and one from a base credential whose root carries no
  `id` (derivation rewrites blank node labels, so nothing identifies the
  original root afterwards and the disclosure would choose it). Give
  credentials an `id` if they are to be used with `ecdsa-sd-2023`.

  **A document whose root takes part in a reference cycle is refused at
  SIGNING and at VERIFICATION.** A presentation carrying a credential whose
  subject links back at it is the shape: it says which node it is about while
  compact and stops saying so once serialized through RDF, so it would verify
  in one form and not another. The same check runs on both paths, which means
  **a document of that shape signed before this release no longer verifies** —
  re-issue or re-present it with the cycle broken, usually by giving the inner
  credential an `id` and referring to it rather than nesting the link back.
  The error names the document rather than the serialization.

  The same applies to a signed document whose root is an unnamed node that
  something else refers to: verification refuses it, not only signing.

- **Unresolvable auth scopes now fail at startup**: every scope listed in an `auth_scopes` entry must name a configured `credential_metadata` scope. A scope that names none previously started fine and produced a DCQL query no wallet could satisfy, failing only after the user had already been sent to their wallet; it is now rejected at config load, so a deployment carrying one will stop starting.

  **Migration:** if APIGW fails to start with `apigw.data_sources.datastore.scopes: ... name no scope in common.credential_metadata`, either add the missing `common.credential_metadata` entry or drop the scope from `auth_scopes`. The error lists every offending `<scope>.auth_scopes.<auth_scope>` pair.

  A `credential_metadata` key present but empty (a YAML typo) is likewise rejected now rather than dereferenced at startup, as is a VCTM document holding the literal `null`, which used to load and then fail every issuance after a successful `/token`.

- **Configuration Refactoring**: Migrated to centralized `key_config` using `pki.KeyConfig` across all services. All signing key configurations now use the unified PKI package structure. Existing configurations will fail validation without these updates.
  
  **Migration:** Update your configuration files with the new `key_config` structure:
  
  **Issuer** (see `issuer` section in [config.yaml](config.yaml)):
  ```yaml
  issuer:
    key_config:
      private_key_path: "/pki/signing_ec_private.pem"
      chain_path: "/pki/signing_ec_chain.pem"
  ```
  
  **Verifier** (see `verifier` section in [config.yaml](config.yaml)):
  ```yaml
  verifier:
    # Shared signing key configuration used for OAuth metadata, OIDC, and OpenID4VP
    key_config:
      private_key_path: "/pki/signing_ec_private.pem"
      chain_path: "/pki/signing_ec_chain.pem"
  ```
  
  **Registry** (see `registry.token_status_lists` section in [config.yaml](config.yaml)):
  ```yaml
  registry:
    token_status_lists:
      key_config:
        private_key_path: "/pki/signing_ec_private.pem"
        chain_path: "/pki/signing_ec_chain.pem"
  ```
  
  **APIGW** (see `apigw` section in [config.yaml](config.yaml)):
  ```yaml
  apigw:
    registry_external_url: "http://registry.example.com:8080"  # New required field
    key_config:
      private_key_path: "/pki/signing_ec_private.pem"
      chain_path: "/pki/signing_ec_chain.pem"
  ```
  
  See complete examples in [config.yaml](config.yaml).

- **Issuer credential-offer UI route**: `GET /offers/:scope/:wallet_id` is now
  `GET /offers/:scope`. The credential offer is wallet-independent, so no
  wallet is selected before it is produced; the single response carries the
  offer once plus one entry per configured wallet. This is the internal
  operator UI's own endpoint, not a wallet-facing one.

### Fixed

- **`eddsa-rdfc-2022` could not verify a verifiable presentation carrying a
  credential** — which is every presentation `openid4vp.VPBuilder` produces.
  `Verify` did two things `Sign` does not:

  - it called `NormalizeVerifiableCredentialGraph()`, which rewrites the
    `verifiableCredential` graph, so a presentation with a credential in it
    canonicalized differently at verification time than at signing time —
    in every serialization, including straight from `Sign`'s return value;
  - it removed only the proofs attached to nodes of a target type read from
    `OriginalJSON()`. That works while `OriginalJSON()` is the compact
    document the caller passed in; it is expanded JSON-LD — a JSON array —
    for a credential re-parsed from `MarshalJSON` output, and then the
    `map[string]any` unmarshal fails, the error is swallowed, and the target
    stays `VerifiableCredential`, which for a presentation removes an
    embedded credential's issuer proof and leaves the presentation's own
    proof in the document being hashed.

  Verification also now checks the proof the document attaches to **itself**,
  read off the document's top-level node, instead of the first proof node a
  search through the document reaches. Taking the first was not merely
  arbitrary: verification USED TO remove every proof when hashing, so a proof
  MOVED from the presentation onto its embedded credential left the hash
  unchanged - someone holding a legitimately signed presentation could move
  the holder's proof down, delete the presentation's own, and have the
  misplaced proof verify with the holder's key.

  Both halves of that are closed now. Hashing is scoped to the root's own
  proofs, so a moved proof no longer leaves the document unchanged, and
  selection is scoped to the root, so a proof the top-level node does not
  carry is not a candidate at all. A document that attaches no proof to
  itself is refused.

  Measured against the old code: a presentation carrying **no** credential
  verified unless it had been re-parsed from expanded JSON; one carrying a
  credential failed in every form. `Verify` now canonicalizes exactly as
  `Sign` does.

  What a signature covers **did** change in the same release — see
  *Data Integrity proofs now secure the document they are attached to*
  under Breaking Changes. That change is not EdDSA-only: it applies to
  `ecdsa-rdfc-2019` as well.

### Changed

- The issuer's `/offers` page now renders one credential offer three ways:
  a QR code (cross-device, carrying the offer by reference), a same-device
  "Open in wallet" button over the W3C Digital Credentials API
  (`openid4vci-v1`, rendered only when such a request can actually be
  fulfilled), and one shortcut button per configured wallet.
- `GET /credential-offer/:credential_offer_uuid` now has a writer: offers
  shown in the issuer UI are persisted under a UUID so the QR can carry the
  offer by reference instead of by value. The UUID is derived from the offer,
  so repeated requests reuse one stored document rather than accumulating —
  `GET /offers/:scope` is unauthenticated, and neither the Mongo nor the SQL
  credential-offer store has an expiry mechanism to bound growth with.
- `GET /offers/:scope` is rate limited, configurable via the new
  `apigw.rate_limit.credential_offer_requests_per_minute` (default 20).

### Note

- The issuer's same-device "Open in wallet" button is present but dormant: no
  shipping browser natively allows `openid4vci-v1`, and the `window.DigitalWallets`
  registry it would otherwise use cannot share a module instance with the
  vendored DC API polyfill (sirosfoundation/dc-api#23). Its gate,
  `isIssuanceAvailable()`, therefore returns false and the button does not
  render.

## [0.3.2] - 2024-04-29

### Change

- Remove eduSeal/Ladok pdf signing service, new repo: https://github.com/SUNET/eduseal

## [0.3.1] - 2024-04-24

## Changed

- Change iso3166-1-alpha-3 to iso3166-1-alpha-2

## [0.3.0] - 2024-04-22

### Added

- Add sd-jwt PDA1 and EHIC creation in Issuer #43
- add Tracing #21
- Add TLS to http server #25
- Add async communication to surrounding system
- Add Swagger endpoint

### Changed

- Fixed API version 2.4 #39
- Got rid of haproxy

### Fixed
