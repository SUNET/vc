# Changelog

## [Unreleased]

### Breaking Changes

- **Unresolvable auth scopes now fail at startup**: every scope listed in an `auth_scopes` entry must name a configured `credential_metadata` scope. A scope that names none previously started fine and produced a DCQL query no wallet could satisfy, failing only after the user had already been sent to their wallet; it is now rejected at config load, so a deployment carrying one will stop starting.

  **Migration:** if APIGW fails to start with `apigw.data_sources.datastore.scopes: ... name no scope in common.credential_metadata`, either add the missing `common.credential_metadata` entry or drop the scope from `auth_scopes`. The error lists every offending `<scope>.auth_scopes.<auth_scope>` pair.

  A `credential_metadata` key present but empty (a YAML typo) is likewise rejected now rather than dereferenced at startup, as is a VCTM document holding the literal `null`, which used to load and then fail every issuance after a successful `/token`.
- **Status-list and DCQL changes** — see the entries below. The Docker image
  still ships `/metadata`: an earlier revision of this branch removed it, but
  the in-repo Fly environment configures `common.credential_metadata` with
  `/metadata/...` paths and mounts nothing of its own, so removing the copy
  left all four services failing at config load. Dropping it from the image
  needs those configurations migrated first, which is its own change.

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

- **`fly/deploy.sh` stops when a `fly` call on an existing app fails**: the
  checks for the MongoDB credentials, OIDC secrets, AS signing key, service
  signing keys and SAML SP keypair read a failed listing as "secret absent",
  then generated and set new values over the live ones. A failed `ips list`
  allocated more IPs, and failed `secrets set`, `status` and `apps destroy`
  calls read as "app missing", "not deployed" and "already gone". Each of
  these calls now stops the script with the app's name and fly's error. A
  call on an app that `fly apps list` does not show is reported as missing,
  so `launch --service <name>` still continues past apps it did not create.
  The app and secret checks read listings of any size.
- **`fly/deploy.sh` keeps the local secrets file in step with Fly**: the
  generated MongoDB URI was written locally after a failed `secrets set`, and
  the OIDC `client_secret` reached Keycloak before a local write that could
  still fail. Both local writes are now prepared before the set and happen
  only after it succeeds. The MongoDB URI goes to `common.mongo.uri`, so a
  file with no `uri:` line receives it and other `uri` keys stay. A secrets
  file that is missing or read-only stops the MongoDB or OIDC step before Fly
  receives anything when the app exists; an absent app gets a "missing" note
  and `launch` continues. When MongoDB's credentials exist and wallet-backend
  lacks `WALLET_STORAGE_MONGODB_URI`, `launch` now sets the URI from the local
  secrets file. When the file holds no generated URI, `launch` stops and names
  the two ways out: restore the file, or reset MongoDB's credentials. An
  absent wallet-backend gets a "missing" note and `launch` continues;
  `launch --service wallet-backend` applies this rule once the app exists.
- **`fly/deploy.sh` registers no duplicate issuer on wallet-backend**: a
  failed issuer listing, an HTTP error or an unparseable body read as "no
  issuers", and the registration POSTed a second issuer. A non-JSON body
  ended the deploy with no message. Each case now skips the registration
  with a message. A `fly proxy` that had already exited ended the deploy
  after the registration; it now counts as stopped.
- **`create_pki.sh` creates private keys owner-only before writing them**:
  LibreSSL's `openssl`, the one macOS ships, honours the umask, so under the
  usual umask 022 the keys were world-readable. A default ACL on the PKI
  directory overrides the umask, so with LibreSSL on Linux another user could
  read `rootCA.key`, `signing_rsa_private.pem` and the client keys. Each key
  file and the nym_auth seed start empty, with mode 600 and no inherited
  ACL entry, before any key material reaches them. A failed or interrupted
  generation removes the file, so the next run generates that key. The EC
  signing key leaves no intermediate file.
- **The Linux dev stack can read its keys**: OpenSSL 1.1 and later write
  private keys 0600, and the script wrote the nym_auth seed 0600, so the
  containers (uid 65532) could not read the keys they mount. On Linux the
  script now grants uid 65532 read access through an ACL entry, and stops
  when `setfacl` is missing or fails. Keys generated earlier keep their
  modes; `make pki-clean pki` regenerates them.
- **MongoDB database names are configurable**: apigw, verifier and registry
  always used the fixed databases `vc`, `verifier` and `vc_registry`. A
  database in `common.mongo.uri` (e.g. `mongodb://host/tenant_a`) only
  selects the authSource and never chose where data went, so deployments
  sharing one MongoDB server silently shared credentials, identity mappings,
  OIDC clients and status lists. New settings
  `common.mongo.apigw_database_name`, `common.mongo.verifier_database_name`
  and `common.mongo.registry_database_name` default to the old names, so
  existing deployments are unaffected. Deployments sharing a MongoDB server
  must give each one distinct names, and a distinct
  `common.ha.cache_database_name`. Changing a name does not move data: copy
  the existing collections to the new database first (for example with
  `mongodump` and `mongorestore --nsFrom/--nsTo`).

- **W3C presentation verification picked a proof by accident.** A verifiable
  presentation holds two Data Integrity proofs - the holder's, over the
  presentation, and the embedded credential's, from the issuer - and both
  reach the suite through `ProofObject()`. The suite verified whichever proof
  node it reached first, which depended on the blank-node ordering json-gold
  happened to assign and, where a proof sat under a map key, on Go's
  randomised map iteration. Nothing tied the signature that was checked to
  the proof whose `proofPurpose`, challenge and domain had been validated.

  The presentation path now names its own proof by `proofValue`
  (`Suite.VerifyProof`), and `common.FindProofNode` traverses in a
  deterministic order. Verification behaviour for a single-proof document is
  unchanged.

### Added

- **Interactive Authorization (OpenID4VCI 1.1)**: an Authorization Challenge
  Endpoint at `POST /authorize-challenge`, off by default and enabled with
  `apigw.delivery.interactive_authorization.enable`. A wallet asks for
  authorization, is answered with an OpenID4VP presentation request, presents
  a credential and receives an authorization code - no browser involved.
  `auth_session` is one-shot and DPoP-bound, and the code must be redeemed at
  `/token` with the same key. SD-JWT VC presentations must carry a Key Binding
  JWT that verifies against the issuer-signed `cnf`, and the credential must
  be within its validity window. Rate limited by the new
  `apigw.rate_limit.authorization_challenge_requests_per_minute` (default 20).
- `openid4vp.CanonicalOrigin` now serialises an origin as a browser would
  (IDNA A-labels, WHATWG IPv6, default ports dropped), and the verifier's
  DC API origin uses it.

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
