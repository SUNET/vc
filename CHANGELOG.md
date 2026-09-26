# Changelog

## [Unreleased]

### Breaking Changes

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
