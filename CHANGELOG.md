# Changelog

## [Unreleased]

### Breaking Changes

- **Data Integrity proofs now secure the document they are attached to.**
  All three cryptosuites — `eddsa-rdfc-2022`, `ecdsa-rdfc-2019` and
  `ecdsa-sd-2023` — used to remove EVERY proof in the graph when
  canonicalizing. A presentation's signature therefore did not cover the issuer
  proof of the credential it carried, so that proof could be stripped or
  swapped with the presentation still verifying.

  What is removed now is **the root's entire proof set** — every proof the
  document attaches to ITSELF, not only the one being created or verified.
  That is what a proof set means: each of its proofs secures the same
  unsecured document, so several parties can sign one document independently
  and each signature stays valid as the others are added or removed. Proofs
  anywhere else are left exactly where they are, so an embedded credential's
  issuer proof is part of the document the presentation secures.

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

  **Signing a bare `@graph` container now roots the document first, in all
  three suites.** Such a container is a document about nothing — the shape
  flattening produces. Root-scoped hashing selected the node inside it, but
  the proof was appended to the container, so it belonged to a wrapper rather
  than to the credential that was hashed; under the VC v2 context, where
  `proof` is defined on credential types, it expanded away altogether. `Sign`
  reported success and returned a document this library then refused. It now
  returns the credential node with the former siblings under `@included`,
  which is the same RDF graph. **Anything signed that way before this release
  never verified** — re-sign it. `ecdsa-sd-2023` was affected twice over,
  since its mandatory pointers resolved against the container while signing
  and against the credential while verifying: a pointer such as `/issuer`
  addressed nothing at all.

  **A proof is written under the absolute predicate whenever the bare term
  `proof` is not known to mean it.** Previously the bare term was also the
  fallback when nothing resolved it — a document already in expanded form,
  which carries no `@context` because every name in it is an IRI, or a context
  defining neither `proof` nor a vocabulary to read it through. A bare term no
  context defines is a RELATIVE IRI, and expansion drops it: `Sign` reported
  success and returned a document with no root proof at all, which this
  library then refused to verify. Such documents now carry
  `https://w3id.org/security#proof`, which expands to itself under any
  context. **Anything signed that way before this release never verified** —
  re-sign it. A document that aliases the predicate still keeps its own
  spelling, so signing twice makes one proof set.

  **Rooting is refused when it would change the document's RDF.** The rewrite
  moves the nodes beside the root into `@included`, and the result is now
  canonicalized and compared against the original before it is returned;
  anything that does not come through unchanged is refused rather than rooted
  into a different graph. Three ways it can fail are known. Nodes beside the
  root never saw the root's own local `@context`, so a term the root redefines
  would change their triples — the scope is restored where JSON-LD allows it,
  which a context holding `@protected` terms does not. `@included` is a
  JSON-LD **1.1** keyword, so a document parsed with
  `ProcessingMode: json-ld-1.0` cannot be rooted at all while anything has to
  move; that one is refused by name. And fragments of one node split across
  several `@graph` entries are now merged before the root is chosen, where
  before they read as several nodes and a perfectly unambiguous document was
  refused for holding "more than one node nothing refers to". Affects
  `ecdsa-sd-2023` derivation and signing of containers only.

  **`RDFCredential.Dataset()` drops the credential's memoized answers.**
  Verification memoizes the proof set, the document hash and the root-scoped
  document, and those are pure functions of the document — but `Dataset()`
  hands out the LIVE dataset and `NormalizeVerifiableCredentialGraph()`
  rewrites it. A stale memo is not merely out of date: it leaves a cached hash
  in place, so a later verification skips the root-stability check and
  authenticates state that is no longer what it checked. Both now clear every
  memo. A caller that only reads the dataset pays one recomputation, since
  nothing here can tell a reader from a mutator.

  **A proof reference is resolved against top-level NODES as well as named
  graphs.** The VC v2 context declares `proof` with `"@container": "@graph"`,
  so a proof becomes a named graph once serialized through RDF. A document
  that aliases the predicate WITHOUT that container does not: the round trip
  flattens its proof into an ordinary top-level node. Resolving the reference
  only against named graphs returned the incomplete LINK as the proof and left
  the real proof node inside the document the signature covers, so such a
  document verified straight from `Sign` and stopped verifying once serialized
  and read back.

  **`credential.IsGraphWrapper` replaces `ld.IsGraph` on compacted documents.**
  `ld.IsGraph` knows only the spellings `@id` and `@index`, so a wrapper in a
  document that aliases either read as an ordinary node: `ecdsa-sd-2023` proof
  removal left the proof's named graph in the supposedly proof-free document,
  and root selection offered that graph as a candidate for what the document
  is about. The graph NAMES a proof link carries are read through the context
  too.

  **`credential.CompactNodeID` takes the document context.** It read only the
  spellings `@id` and `id` while root selection resolved any alias, so a
  flattened document aliasing `@id` returned `""` for the root AND for every
  other node — and `ecdsa-sd-2023` proof removal, comparing those answers,
  found every node equal to the root and stripped the embedded credentials'
  proofs along with the root's. The exact failure this release exists to
  remove, reached through an alias. **Signature change:**
  `CompactNodeID(node, context, options)`.

  Canonicalization also no longer inherits a stale `Format` or `InputFormat`
  from a reused option set — both describe a call whose input or output is
  N-Quads, and a credential's is JSON.

  **An explicit `"@context": null` resets the `expandContext` too.** It is a
  RESET, and it clears everything before it — measured, the same document
  expands to its triples with no `@context` member and to **nothing** with an
  explicit null. Term resolution went on applying the `expandContext` either
  way, because a JSON null and an absent member both arrive as a nil context,
  so a new proof was written under an alias the document had just disabled and
  expansion dropped it: `Sign` succeeded and returned a document with no root
  proof. Finding the root's own proofs still takes the bare name, because
  missing one is the worse failure and a member the reset turned into a
  relative IRI carries no triples either way.

  **The OpenID4VP handler resolves a proof graph by the reference that names
  it.** A root proof that survived a round trip through RDF is a reference to a
  named graph beside the document, and an expanded credential carrying an
  embedded secured credential has more than one. The handler accepted the
  FIRST, so top-level array order — which is not signed — decided which proof
  was reported: a document could be reordered until `Claims["proof"]` named the
  nested issuer's proof while verification checked the root's. An unresolvable
  reference now reports no proof rather than someone else's.

  **Root matching reads a node's own `@context` and any alias of `@id`.** A
  `@graph` entry may declare its own prefix and use it in its identifier, and
  JSON-LD lets a context alias `@id` to any term. `RootID` works on the
  EXPANDED document and resolved both; root matching read entries under the
  container's context alone and knew only the spellings `@id` and `id`, so the
  two disagreed and **documents of either shape were refused at signing** as
  though their root had disappeared, or as holding more than one node nothing
  refers to. They now sign. Fragments are merged through the same reading, so a
  node split across `@graph` entries and spelled through a context coalesces
  like any other.

  **`RDFCredential.CanonicalForm` now honours the options the credential was
  parsed with.** It built fresh defaults — no caller document loader, no
  `expandContext`, no base, no processing mode — while root selection,
  proof-key selection and proof-scope removal all re-expanded under the
  credential's own options. A credential was therefore READ one way and
  SIGNED another, and the canonical form is the only thing a Data Integrity
  signature covers. **A credential parsed with non-default options produces a
  different document hash than before**, so proofs made over one no longer
  verify — re-sign them. Credentials parsed with default options are
  unaffected.

  The suites now return their signed and derived output parsed with the SOURCE
  credential's options too, rather than fresh defaults — otherwise a credential
  is signed under one RDF interpretation and handed back under another, and
  `Sign` output fails `Verify`. The VC-v2 options stay where they belong, on
  proof-configuration hashing.

  **Canonicalization goes through the credential's own RDF conversion.**
  json-gold's `Normalize` builds fresh options for its RDF step and carries
  only the base, the document loader and the processing mode across, so
  everything else was dropped. A credential whose terms come from an
  `expandContext` canonicalized to **nothing** — no error, no quads, and a Data
  Integrity signature over the empty string, the same signature for every
  document of that shape. A credential parsed with `ProduceGeneralizedRdf` kept
  its blank-node-predicate quads in its dataset and left them OUT of the
  canonical form, so those quads could be added, changed or removed without
  invalidating any signature. The document is now converted to RDF under the
  credential's own options and that DATASET canonicalized directly — not a
  document and not an N-Quads string, since a blank node in predicate position
  is not valid N-Quads and the round trip drops exactly the quads generalized
  RDF exists for. **Credentials signed under either option before this release
  carry a proof that does not cover what they say** and must be re-signed.

  `RDFCredential.MarshalJSON` and `ToCompactJSON` take the same route, for the
  same reason: they serialized the dataset to N-Quads and read it back, so a
  generalized-RDF credential could not be serialized at all — and the
  root-stability check every suite runs before signing and before verifying
  reads the root off `MarshalJSON`, so such a credential was neither signable
  nor verifiable. `ToCompactJSON` also set `Format` on the credential's own
  options **in place**, so a credential that had once been compacted parsed
  JSON as N-Quads ever after.

  **The OpenID4VP handler's `Claims["proof"]` reports the proof that
  verified.** Extraction resolves only the first proof reference, so a proof
  SET carrying a forged proof ahead of a genuine one had the claims naming the
  REJECTED proof while every other field on the result described the accepted
  one. Extraction itself also merges a proof node split across several members
  of its graph, instead of reporting whichever fragment came first — unsigned
  member order decided which fields appeared.

  **A document whose root takes part in a reference cycle is refused at
  SIGNING and at VERIFICATION.** A presentation carrying a credential whose
  subject links back at it is the shape: it says which node it is about while
  compact and stops saying so once serialized through RDF, so it would verify
  in one form and not another. The same check runs on both paths, which means
  **a document of that shape signed before this release no longer verifies** —
  re-issue or re-present it with the cycle broken, usually by giving the inner
  credential an `id` and referring to it rather than nesting the link back.
  The error names the document rather than the serialization.

  Three further shapes are refused on BOTH paths for the same reason — the
  document would be about one node while compact and another once serialized
  through RDF, so a proof on one would be read as the other's. A document
  whose root is an unnamed node that something else refers to; one whose root
  is unnamed and which uses `@reverse`; and one with no single top-level node
  that nothing refers to, which includes two such nodes as well as none. Each
  error names the document rather than the serialization. **Documents of these
  shapes signed before this release no longer verify.**

  **A proof's key must belong to the credential's issuer.** The OpenID4VP
  handler checked the (unsigned) `issuer` claim against its trusted-issuer
  list and, separately, asked its resolver for the key the proof names.
  Nothing joined the two, so in a trust framework holding several issuers —
  where every issuer's key resolves — a credential claiming one issuer could
  be signed with anybody else's resolvable key and was reported as that
  issuer's.

  A resolver may now implement `openid4vp.VC20IssuerAuthorizer` (may THIS
  issuer assert with THIS key, for this proof purpose) and its answer is
  final. `pkg/trust`'s `TrustEvaluator` already takes a subject, a key and an
  action, so an adapter over it is small — **but no adapter in this
  repository implements it yet**, so every deployment currently takes the
  fallback below.

  **Migration:** without an authorizer the handler requires the verification
  method to BE the issuer or to sit under it — `did:example:issuer#key-1`
  under `did:example:issuer`, `https://issuer.example/keys/1` under
  `https://issuer.example`. **A credential signed with a key delegated to a
  different identifier is now refused**, even where the trust framework
  authorizes that delegation. If you rely on delegation, implement
  `VC20IssuerAuthorizer` on your resolver; that path accepts it. The fallback
  is a deliberate approximation, not the intended end state — an identifier
  under the issuer is not proof the key sits in that issuer's
  `assertionMethod` relationship either.

  **An expanded verifiable presentation is no longer accepted by the
  OpenID4VP handler.** It used to verify the proofs the DOCUMENT attaches to
  itself — the holder's, for a presentation — while reporting the issuer,
  subject and trust decision of the embedded credential, whose own proof was
  never checked. Compact presentations are unaffected: they are unwrapped to
  the credential they carry and that credential's proof is what gets verified.
  **Migration:** send presentations in compact JSON-LD. A caller that has only
  the expanded form should extract the credential and present that. Expanded
  CREDENTIALS are unaffected.

  **A document may attach at most 32 proofs to itself.** Verification refuses
  more before checking any signature — the list is read off the document, so
  its length is the sender's choice, and each candidate costs a JSON-LD
  canonicalization and a signature check on input nobody has authenticated
  yet. Signing refuses to add the 33rd for the same reason, so the limit
  cannot be reached by accident. A real proof set is a handful of signers; a
  previously signed document carrying more than 32 stops verifying and has to
  be re-issued with fewer.

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
