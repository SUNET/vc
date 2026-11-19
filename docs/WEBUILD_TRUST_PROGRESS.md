# WE BUILD trust for Fly dev: progress summary

Status on 2026-11-09 for todo item 10 (access and registration certificates, Pub-EAA registry entry, trusted lists).

## Done

1. **Verifier access certificate (WRPAC):** issued by the Raidiam WE BUILD sandbox (EC P-256). It is deployed on Fly dev, and the request-object chain verifies up to the WE BUILD root.
2. **Issuer in the WE BUILD Pub-EAA trusted list (IDunion):** SUNET is listed as `PubEAA/Issuance`, status `notified`.
3. **Issuer signing key:** switched to the IDunion certificate and deployed. The wallet shows the issuer as trusted, a PID was issued, and the wallet `/add` flow works.
4. **Tooling and docs:** `fly/deploy.sh` has new `wrpac` and `idunion` commands. There are scripts for the CSRs, and [TRUST_AND_IDENTITY.md](TRUST_AND_IDENTITY.md) describes how to get a WRPAC.

## Blocked

1. **Registration certificate (WRPRC) for the verifier:** the Raidiam sandbox and its data API were down (HTTP 500). It also needs a transport certificate for the registry API.
2. **go-trust cannot verify the WE BUILD lists:**
   - The JSON list of lists has an embedded `{protected, signature}` signature that go-trust cannot parse ([go-trust#238](https://github.com/sirosfoundation/go-trust/issues/238)).
   - XML lists cannot be verified when `trust_anchor_bundle` is set ([go-trust#239](https://github.com/sirosfoundation/go-trust/issues/239)).
   - Loaded without verification, the Pub-EAA list works: our issuer chain returned `decision: true`. This was tested locally only.
3. **Wallet rejects the verifier:** the wallet reports "Verifier is not trusted" for the OpenID4VP flow. The cause is not found yet; see [WALLET_VERIFIER_NOT_TRUSTED.md](WALLET_VERIFIER_NOT_TRUSTED.md).

## Open questions

1. Does the issuer also need an access certificate (WRPAC) or a registration certificate (WRPRC), or is the trusted-list entry enough?
2. Is it acceptable that the IDunion list CA is self-signed and sits in the x5c chain? This may conflict with HAIP.
3. Which signer certificates must `trust_anchor_bundle` hold so that go-trust loads the IDunion Pub-EAA list with verification on? go-trust 0.29.0 fixed #238 and #239, but a local run with only the two WP4 anchors loaded no entities.
4. Wallet reading of trusted lists has not been started.

## Left to do

1. Find why the wallet reports "Verifier is not trusted" (wallet-backend and go-trust logs, request object SAN, AuthZEN evaluation of the verifier chain).
2. Get a registration certificate (WRPRC) for the verifier: needs the Raidiam sandbox back, a transport certificate, and a script for the registry API. Then enable `registration_certificate` and `trusted_roots_path` in `fly/dev/config.yaml`.
3. Make go-trust on Fly dev verify the WE BUILD lists. It already runs `fly/dev/go-trust/config.yaml` with no whitelist (release v75, 2026-11-10) and loads 12 lists, 96 entities, unverified. Add the signer anchors (`trust_anchor_bundle`, mounted as a `[[files]]` entry in `fly/dev/go-trust/fly.toml`), redeploy, and check the log shows no `signature verification failed` for the Pub-EAA list.
4. Make the wallet read trusted lists (wallet-backend `WALLET_TRUST_DEFAULT_ENDPOINT`, `cmd/wallet`).
5. Ask WP4 whether the issuer needs a WRPAC or WRPRC, and whether the self-signed list CA in x5c is acceptable under HAIP.
6. Inspect the x5c chain of an issued credential.
7. Decide on the script name: keep `create_wrprc.sh` for the IDunion CSR, or revert to `create_idunion_csr.sh` and reserve `create_wrprc.sh` for a real WRPRC request.
8. Clean up: test containers `gt-test`, `gt-test2` and images `gt-local-test`, `gt-local-test2`, `gt-local-test3` on the Docker host; stale key files in `developer_tools/pki/webuild/` (`issuer-idunion.*`, `*-rejected.*`; keep `issuer-wrprc-idunion.key`).
9. Update `todo.md` item 10 to match, and commit the uncommitted changes.
10. write down the complete flow.

## Not changed on Fly

- Credentials issued before the key swap no longer verify against the new `/jwks`.
