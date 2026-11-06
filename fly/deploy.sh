#!/usr/bin/env bash
# Fly.io deployment helper for VC services.
# Usage:
#   ./fly/deploy.sh <command> --profile {dev|demo} [options]
#
# Profiles:
#   dev   -> reads fly/dev/,  app prefix "sunet-vc",      image tag ":local"
#   demo  -> reads fly/demo/, app prefix "sunet-vc-demo", image tag ":demo"
#
# The two profile trees are fully independent copies. Editing fly/dev/ can
# never affect a demo deploy, and vice versa — that isolation is the whole
# point. There is no shared template layer; if you want a dev fix in demo,
# port it by hand (typically: diff -u fly/dev fly/demo, then copy).
#
# Commands:
#   launch     - Create Fly apps for all services (first time only)
#   deploy     - Deploy all services (or specify --service <name>)
#   secrets    - Print the secrets file path for the profile
#   status     - Show status of all services
#   logs       - Tail logs for a service (requires --service)
#   destroy    - Destroy all Fly apps (requires --confirm)
#
# Options:
#   --profile <name>   Environment profile: dev | demo (required for most cmds)
#   --service <name>   Target a specific service
#   --region <code>    Override primary region (default: arn)
#   --env <name>       Override app prefix directly (advanced; skips profile)
#   --tag <tag>        Override docker image tag (advanced; skips profile)
#   --org <name>       Fly organisation (default: sirosfoundation)
#   --confirm          Required for destructive operations

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export FLYCTL_INSTALL="${FLYCTL_INSTALL:-$HOME/.fly}"
export PATH="$FLYCTL_INSTALL/bin:$PATH"

SERVICES=(mongodb go-trust oidc registry issuer verifier apigw wallet-backend wallet-frontend wallet)
REGION="${FLY_REGION:-arn}"
ENV_PREFIX="${FLY_ENV_PREFIX:-}"
VC_IMAGE_TAG="${FLY_VC_IMAGE_TAG:-}"
FLY_ORG="${FLY_ORG:-sirosfoundation}"
PROFILE=""
CONFIRM=""
TARGET_SERVICE=""
MONGO_ADMIN_USER="admin"

usage() {
    sed -n '2,/^$/s/^# //p' "$0"
    exit 1
}

die() { echo "Error: $*" >&2; exit 1; }

# Runs `fly $3..`, storing its stdout in the variable named $1 and its stderr
# in the variable named $2. Returns fly's exit status.
fly_capture() {
    local _out_var="$1" _err_var="$2" _err_file _out _status=0
    shift 2
    _err_file="$(mktemp)"
    _out="$(fly "$@" 2>"$_err_file")" || _status=$?
    printf -v "$_err_var" '%s' "$(cat "$_err_file")"
    rm -f "$_err_file"
    printf -v "$_out_var" '%s' "$_out"
    return "$_status"
}

# Returns 0 when `fly apps list` shows app $1 and 1 when it does not. A failed
# listing stops the script with $2 and fly's error.
app_listed() {
    local _app="$1" _context="$2" _apps _err
    fly_capture _apps _err apps list --json || die "$_context: $_err"
    grep -q "\"$_app\"" <<<"$_apps"
}

# Returns when Fly app $1 is absent, and stops with fly's error $3 when it
# exists. $2 names the failed call. `launch --service <name>` provisions apps
# it did not create, so a failure on an absent app is expected; any other
# failure would read as "nothing there" and replace live state.
require_app_absent() {
    local _app="$1" _call="$2" _call_err="$3"
    if app_listed "$_app" "$_call of $_app failed, and so did listing the apps"; then
        die "$_call of $_app failed: $_call_err"
    fi
}

# Stores the secrets of Fly app $1, as JSON, in the variable named $2. An
# absent app stores "[]".
read_app_secrets() {
    local _app="$1" _secrets_var="$2" _json _err
    if fly_capture _json _err secrets list --app "$_app" --json; then
        printf -v "$_secrets_var" '%s' "$_json"
        return 0
    fi
    require_app_absent "$_app" "listing the secrets" "$_err"
    printf -v "$_secrets_var" '%s' '[]'
}

# Sets the secrets $2.. on Fly app $1. Returns 1 after an "app missing" note
# when the app is absent.
set_app_secrets() {
    local _app="$1" _err
    shift
    if { _err="$(fly secrets set --app "$_app" "$@" 2>&1 1>&3 3>&-)"; } 3>&1; then
        return 0
    fi
    require_app_absent "$_app" "setting secrets" "$_err"
    echo "    ($_app missing; secrets left unset)"
    return 1
}

# The next content of the secrets file, named <target>.<random> beside the file a
# symlink resolves to. Fly secrets are write-only and a failed write can destroy
# the file, so a new value reaches the file by rename. Exit removes it.
secrets_candidate=""

remove_secrets_candidate() {
    [[ -z "$secrets_candidate" ]] || rm -f "$secrets_candidate"
    secrets_candidate=""
}
trap remove_secrets_candidate EXIT

# Creates the candidate for secrets file $1. Returns 1 when the directory refuses
# it.
open_secrets_candidate() {
    local _file="$1" _target
    _target="$(readlink -f "$_file")" || die "resolving $_file failed"
    secrets_candidate="$(mktemp "$_target.XXXXXX" 2>/dev/null)"
}

# Writes $1 to the candidate, with the mode of the file it replaces. A failure
# stops the script.
write_secrets_candidate() {
    local _content="$1"
    if ! cp -p "${secrets_candidate%.*}" "$secrets_candidate" ||
        ! printf '%s\n' "$_content" > "$secrets_candidate"; then
        die "writing $secrets_candidate failed"
    fi
}

# Renames the candidate over the file it replaces. A failure keeps the candidate
# and stops the script, naming the candidate as the holder of $1.
record_secrets_candidate() {
    local _held="$1" _candidate="$secrets_candidate"
    secrets_candidate=""
    mv -f "$_candidate" "${_candidate%.*}" \
        || die "replacing ${_candidate%.*} failed; $_candidate holds $_held"
}

# Decides whether a secret generated for Fly app $2 may be sent. Secrets file $1
# must be able to receive secret $3 first. Returns 0 with the candidate open when
# the file is writable and its directory accepts the candidate. Otherwise returns
# 1 after an "app missing" note when the app is absent, and stops when it exists.
secrets_file_can_record() {
    local _file="$1" _app="$2" _secret="$3" _problem="is missing or read-only"
    if [[ -f "$_file" && -w "$_file" ]]; then
        open_secrets_candidate "$_file" && return 0
        _problem="sits in a directory that refuses a temp file"
    fi
    if app_listed "$_app" "$_file $_problem, and listing the apps failed"; then
        die "$_file $_problem; it must receive $_secret before $_app does"
    fi
    echo "    ($_app missing; secrets left unset)"
    return 1
}

require_flyctl() {
    command -v fly >/dev/null 2>&1 || die "flyctl not found. Install: https://fly.io/docs/flyctl/install/"
}

require_jq() {
    command -v jq >/dev/null 2>&1 || die "jq not found. Install: https://jqlang.github.io/jq/download/ (needed for idempotent wallet-backend issuer registration)."
}

require_yq() {
    command -v yq >/dev/null 2>&1 || die "yq not found. Install: https://github.com/mikefarah/yq"
}

apply_profile() {
    case "$PROFILE" in
        dev)
            ENV_PREFIX="${ENV_PREFIX:-sunet-vc}"
            VC_IMAGE_TAG="${VC_IMAGE_TAG:-local}"
            ;;
        demo)
            ENV_PREFIX="${ENV_PREFIX:-sunet-vc-demo}"
            VC_IMAGE_TAG="${VC_IMAGE_TAG:-demo}"
            ;;
        "")
            ;;
        *) die "Unknown profile: $PROFILE (valid: dev, demo)" ;;
    esac
}

require_profile_vars() {
    [[ -n "$ENV_PREFIX" ]]   || die "No profile selected. Pass --profile dev|demo (or --env <prefix> --tag <tag>)."
    [[ -n "$VC_IMAGE_TAG" ]] || die "No image tag. Pass --profile dev|demo (or --env <prefix> --tag <tag>)."
}

app_name() {
    echo "${ENV_PREFIX}-$1"
}

secrets_file_path() {
    echo "${ROOT_DIR}/secrets.${ENV_PREFIX}.yaml"
}

# Directory holding this profile's committed configs. Deploys read directly
# from here — there is no render/staging step.
profile_dir() {
    case "$PROFILE" in
        dev)  echo "${SCRIPT_DIR}/dev"  ;;
        demo) echo "${SCRIPT_DIR}/demo" ;;
        *)    die "profile_dir requires --profile dev|demo" ;;
    esac
}

# Prints the MongoDB URI that authenticates with password $1 on app $2.
mongo_uri_for() {
    local _pass="$1" _app="$2"
    printf '%s\n' "mongodb://${MONGO_ADMIN_USER}:${_pass}@${_app}.internal:27017/?authSource=admin"
}

# Prints the MongoDB URI that launch generated for app $2, read from secrets
# file $1. Returns 1 when the file is absent or holds another URI, such as the
# example placeholder.
local_mongo_uri() {
    local _file="$1" _app="$2" _uri _pass
    [[ -f "$_file" ]] || return 1
    _uri="$(yq -r '.common.mongo.uri // ""' "$_file")"
    _pass="${_uri#mongodb://"$MONGO_ADMIN_USER":}"
    _pass="${_pass%%@*}"
    [[ "$_pass" =~ ^[0-9a-f]{48}$ ]] || return 1
    [[ "$_uri" == "$(mongo_uri_for "$_pass" "$_app")" ]] || return 1
    printf '%s\n' "$_uri"
}

# Sets WALLET_STORAGE_MONGODB_URI to $2 on wallet-backend app $1.
set_wallet_backend_mongo_uri() {
    local _app="$1" _uri="$2"
    echo "==> Setting Mongo URI for $_app"
    if set_app_secrets "$_app" WALLET_STORAGE_MONGODB_URI="$_uri"; then
        echo "    Mongo URI set"
    fi
}

cmd_launch() {
    require_flyctl
    require_yq
    require_profile_vars
    echo "==> Launching Fly apps (prefix=${ENV_PREFIX}, tag=${VC_IMAGE_TAG}, region=${REGION})"
    echo ""
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"
        if fly status --app "$app" >/dev/null 2>&1; then
            echo "  [skip] $app already exists"
            continue
        fi
        echo "  [create] $app"
        fly apps create "$app" --org "$FLY_ORG" || die "Failed to create app: $app"
    done
    echo ""

    # Fly's DNS only returns records for apps that have a public IP. `fly apps
    # create` does not auto-allocate — apps end up NXDOMAIN until the first
    # `fly launch`-style deploy or an explicit allocation. Do it here so the
    # first `deploy` is enough to make the app reachable.
    echo "==> Ensuring public IPs for all apps"
    local ips_json ips_err
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"
        if ! fly_capture ips_json ips_err ips list --app "$app" --json; then
            require_app_absent "$app" "listing the IPs" "$ips_err"
            echo "  ($app missing; IPs left unallocated)"
            continue
        fi
        if ! grep -qE '"Type":\s*"(shared_v4|v4)"' <<<"$ips_json"; then
            echo "  [ipv4] $app"
            fly ips allocate-v4 --shared --app "$app" 2>/dev/null || echo "    (failed; check manually)"
        fi
        if ! grep -q '"Type":\s*"v6"' <<<"$ips_json"; then
            echo "  [ipv6] $app"
            fly ips allocate-v6 --app "$app" 2>/dev/null || echo "    (failed; check manually)"
        fi
    done
    echo ""

    local secrets_file
    secrets_file="$(secrets_file_path)"

    local mongo_app mongo_pass mongo_uri="" mongo_secrets mongo_creds_set=0
    mongo_app="$(app_name "mongodb")"

    # Idempotent: if MongoDB already has creds, keep them. Rotating
    # MONGO_INITDB_ROOT_PASSWORD after the data dir is initialised does NOT
    # change the on-disk user — it desyncs the whole stack (apigw/wallet-backend
    # end up with a URI that no longer authenticates). Only generate + set on
    # first launch.
    read_app_secrets "$mongo_app" mongo_secrets
    if grep -q '"MONGO_INITDB_ROOT_PASSWORD"' <<<"$mongo_secrets"; then
        echo "==> MongoDB secrets already set for $mongo_app (skipping)"
        mongo_creds_set=1
    else
        # hex, not base64: password is embedded in a URI, must be URL-safe.
        mongo_pass="$(openssl rand -hex 24)"

        if [[ ! -f "$secrets_file" ]]; then
            cp "${ROOT_DIR}/secrets.example.yaml" "$secrets_file"
            echo "    Created $secrets_file from secrets.example.yaml"
        fi

        echo "==> Setting MongoDB secrets for $mongo_app"
        if secrets_file_can_record "$secrets_file" "$mongo_app" "the MongoDB password"; then
            local generated_mongo_uri mongo_secrets_content
            generated_mongo_uri="$(mongo_uri_for "$mongo_pass" "$mongo_app")"
            mongo_secrets_content="$(yq ".common.mongo.uri = \"$generated_mongo_uri\"" "$secrets_file")"
            write_secrets_candidate "$mongo_secrets_content"

            if set_app_secrets "$mongo_app" \
                MONGO_INITDB_ROOT_USERNAME="$MONGO_ADMIN_USER" \
                MONGO_INITDB_ROOT_PASSWORD="$mongo_pass"; then
                echo "    MongoDB secrets set"
                record_secrets_candidate "the value Fly accepted"
                echo "    Updated $secrets_file with MongoDB URI"
                mongo_uri="$generated_mongo_uri"
            else
                remove_secrets_candidate
            fi
        fi
    fi

    local oidc_app apigw_client_secret demo_user_password oidc_first_launch oidc_secrets
    oidc_app="$(app_name "oidc")"
    oidc_first_launch=0

    # Idempotent: Keycloak's realm import runs once on first boot and stores
    # the client_secret + user password hashes in its H2 DB. Rotating these
    # env vars later does NOT change what's in the DB — it desyncs apigw's
    # secrets file from Keycloak. Only set on first launch.
    read_app_secrets "$oidc_app" oidc_secrets
    if grep -q '"APIGW_OIDC_CLIENT_SECRET"' <<<"$oidc_secrets"; then
        echo "==> OIDC secrets already set for $oidc_app (skipping)"
    else
        oidc_first_launch=1
        apigw_client_secret="$(openssl rand -hex 24)"
        # 4 chars for live demos: 3 lowercase letters + 1 trailing digit.
        # Shared by every realm user (including admin@sunet.se) — an accepted
        # demo tradeoff: these environments are throwaway and rebuilt often,
        # not production authorisation surfaces.
        demo_user_password="$(LC_ALL=C awk 'BEGIN{srand();s="";for(i=0;i<3;i++)s=s substr("abcdefghjkmnpqrstuvwxyz",int(rand()*23)+1,1);print s int(rand()*10)}')"

        echo "==> Setting OIDC secrets for $oidc_app"
        if secrets_file_can_record "$secrets_file" "$oidc_app" "apigw's OIDC client_secret"; then
            # The local file and Keycloak must hold the same client_secret. A
            # failed set leaves the file unchanged, so apigw never ships a secret
            # Keycloak lacks.
            local oidc_secrets_content
            oidc_secrets_content="$(yq ".apigw.auth_providers.oidc.registration.preconfigured.client_secret = \"$apigw_client_secret\"" "$secrets_file")"
            write_secrets_candidate "$oidc_secrets_content"

            if set_app_secrets "$oidc_app" \
                APIGW_OIDC_CLIENT_SECRET="$apigw_client_secret" \
                DEMO_USER_PASSWORD="$demo_user_password"; then
                echo "    OIDC secrets set"
                # Printed first: the candidate omits the password, and Fly never
                # returns it.
                echo "    Demo user password (Keycloak realm users): $demo_user_password"
                record_secrets_candidate "the value Fly accepted"
                echo "    Updated $secrets_file with apigw OIDC client_secret (auth_providers)"
            else
                remove_secrets_candidate
            fi
        fi
    fi

    # api_auth.oidc.client_secret mirrors the preconfigured client_secret.
    # Reconcile on every deploy so upgrades of existing environments (where
    # the first-launch branch above is skipped) still get the field populated
    # without rotating the Keycloak secret. yq is a hard prerequisite (see
    # require_yq at the top of cmd_launch), so no fallback branch is needed.
    if [[ -f "$secrets_file" ]]; then
        local existing_client_secret
        existing_client_secret="$(yq -r '.apigw.auth_providers.oidc.registration.preconfigured.client_secret // ""' "$secrets_file")"
        if [[ -n "$existing_client_secret" && "$existing_client_secret" != "null" ]]; then
            if [[ ! -w "$secrets_file" ]]; then
                echo "    ($secrets_file is read-only; apigw.api_server.api_auth.oidc.client_secret left as is)"
            elif ! open_secrets_candidate "$secrets_file"; then
                echo "    ($secrets_file sits in a directory that refuses a temp file; apigw.api_server.api_auth.oidc.client_secret left as is)"
            else
                local reconciled_secrets_content
                reconciled_secrets_content="$(yq ".apigw.api_server.api_auth.oidc.client_secret = \"$existing_client_secret\"" "$secrets_file")"
                write_secrets_candidate "$reconciled_secrets_content"
                record_secrets_candidate "the reconciled secrets file"
                echo "    Reconciled apigw.api_server.api_auth.oidc.client_secret in $secrets_file"
            fi
        fi
    fi

    # Keycloak's realm import is one-shot: on an existing environment the
    # newly added admin@sunet.se user and email protocol mapper won't appear
    # in the running realm. Warn the operator so they either re-import
    # manually (Keycloak admin UI → Realm → Partial import) or destroy and
    # re-launch the oidc app to get a fresh realm from realm-vc.json.
    if [[ "$oidc_first_launch" -eq 0 ]]; then
        echo "    NOTE: realm-vc.json changes (admin@sunet.se user, email mapper)"
        echo "          only apply on first launch. To pick them up on an existing"
        echo "          environment: fly ssh console --app $oidc_app and re-import"
        echo "          the realm, or 'fly apps destroy $oidc_app' and re-launch."
    fi

    local wallet_backend_app as_key_pem as_key_b64 wallet_backend_secrets
    wallet_backend_app="$(app_name "wallet-backend")"
    echo "==> Setting AS signing key for $wallet_backend_app"
    read_app_secrets "$wallet_backend_app" wallet_backend_secrets
    if grep -q '"AS_SIGNING_KEY_PEM"' <<<"$wallet_backend_secrets"; then
        echo "    (AS_SIGNING_KEY_PEM already set, leaving in place)"
    else
        as_key_pem="$(openssl ecparam -name prime256v1 -genkey -noout)"
        as_key_b64="$(printf '%s' "$as_key_pem" | base64 | tr -d '\n')"
        if set_app_secrets "$wallet_backend_app" AS_SIGNING_KEY_PEM="$as_key_b64"; then
            echo "    AS signing key set"
        fi
    fi

    # A freshly generated URI replaces wallet-backend's. With MongoDB's
    # credentials already set, a missing URI comes back from the local file:
    # Fly secrets are write-only, so the file is its only copy. An absent
    # wallet-backend waits for `launch --service wallet-backend`, which reaches
    # this check again. read_app_secrets stores "[]" for an absent app, so only
    # that listing needs `fly apps list`. An empty $mongo_uri with
    # $mongo_creds_set at 0 means the MongoDB app is absent.
    if [[ -n "$mongo_uri" ]]; then
        set_wallet_backend_mongo_uri "$wallet_backend_app" "$mongo_uri"
    elif [[ "$mongo_creds_set" -eq 0 ]]; then
        echo "    ($mongo_app missing; Mongo URI on $wallet_backend_app unchanged)"
    elif grep -q '"WALLET_STORAGE_MONGODB_URI"' <<<"$wallet_backend_secrets"; then
        echo "==> Mongo URI on $wallet_backend_app left in place (MongoDB creds unchanged)"
    elif [[ "$wallet_backend_secrets" == "[]" ]] \
        && ! app_listed "$wallet_backend_app" "$wallet_backend_app lacks WALLET_STORAGE_MONGODB_URI, and listing the apps failed"; then
        echo "    ($wallet_backend_app missing; Mongo URI left unset)"
    else
        mongo_uri="$(local_mongo_uri "$secrets_file" "$mongo_app")" \
            || die "$wallet_backend_app lacks WALLET_STORAGE_MONGODB_URI, and $secrets_file holds no generated URI for $mongo_app. Restore $secrets_file, or reset $mongo_app's credentials: destroy it with its volume and run launch again."
        set_wallet_backend_mongo_uri "$wallet_backend_app" "$mongo_uri"
    fi

    # Signing key material shared across apigw/issuer/verifier/registry.
    # fly.toml mounts these as files via [[files]] secret_name = ...; without
    # them the containers crash-loop and 'fly deploy' hits the machine-state
    # timeout on the first push to a fresh env.
    local pki_dir signing_key_b64 signing_chain_b64
    pki_dir="${ROOT_DIR}/developer_tools/pki"
    if [[ -f "${pki_dir}/signing_ec_private.pem" && -f "${pki_dir}/signing_ec_chain.pem" ]]; then
        signing_key_b64="$(base64 < "${pki_dir}/signing_ec_private.pem" | tr -d '\n')"
        signing_chain_b64="$(base64 < "${pki_dir}/signing_ec_chain.pem" | tr -d '\n')"
        for svc in apigw issuer verifier registry; do
            local svc_app svc_secrets
            svc_app="$(app_name "$svc")"
            echo "==> Setting signing secrets for $svc_app"
            read_app_secrets "$svc_app" svc_secrets
            if grep -q '"SIGNING_EC_PRIVATE_KEY"' <<<"$svc_secrets"; then
                echo "    (SIGNING_EC_PRIVATE_KEY already set, leaving in place)"
            else
                if set_app_secrets "$svc_app" \
                    SIGNING_EC_PRIVATE_KEY="$signing_key_b64" \
                    SIGNING_EC_CHAIN="$signing_chain_b64"; then
                    echo "    Signing secrets set"
                fi
            fi
        done
    else
        echo "WARNING: no ${pki_dir}/signing_ec_{private,chain}.pem found;"
        echo "         set SIGNING_EC_PRIVATE_KEY / SIGNING_EC_CHAIN manually on"
        echo "         apigw/issuer/verifier/registry, or run make dev-pki first."
    fi

    # apigw's SAML SP keypair, mounted via [[files]] in fly/<profile>/apigw/fly.toml.
    # See provision_apigw_saml_sp_keypair for the rationale.
    provision_apigw_saml_sp_keypair
    provision_apigw_nym_auth_secrets

    echo ""
    echo "==> Apps created. Next: ./fly/deploy.sh deploy --profile ${PROFILE:-dev}"
}

# apigw's SAML SP keypair, mounted via [[files]] in fly/<profile>/apigw/fly.toml.
# Only apigw needs it, and only profiles that enable SAML mount it. The
# cert/key aren't checked into developer_tools/pki, so we self-provision
# a throwaway keypair on first launch (or first auto-create deploy) to make
# a fresh 'fly deploy' actually boot instead of crashing in tls.LoadX509KeyPair.
provision_apigw_saml_sp_keypair() {
    local apigw_app saml_cert_b64 saml_key_b64 saml_tmp secrets_json
    apigw_app="$(app_name "apigw")"
    # Skip only when BOTH secrets exist. A partial rotation that leaves only
    # the cert would otherwise pass this guard and apigw would fail to load
    # the mounted keypair on startup.
    read_app_secrets "$apigw_app" secrets_json
    if grep -q '"SAML_SP_CERT"' <<<"$secrets_json" \
        && grep -q '"SAML_SP_KEY"' <<<"$secrets_json"; then
        echo "==> SAML SP secrets already set for $apigw_app (skipping)"
        return 0
    fi
    echo "==> Provisioning SAML SP keypair for $apigw_app"
    saml_tmp="$(mktemp -d)"
    # Self-signed cert; SP metadata publishes the pubkey, IdPs pin it out-of-band.
    # 10 years is well beyond dev/demo rotation cadence.
    if openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "${saml_tmp}/saml_sp.key" \
            -out "${saml_tmp}/saml_sp.crt" \
            -days 3650 \
            -subj "/CN=${apigw_app}.fly.dev/O=SUNET VC" \
            >/dev/null 2>&1; then
        saml_cert_b64="$(base64 < "${saml_tmp}/saml_sp.crt" | tr -d '\n')"
        saml_key_b64="$(base64 < "${saml_tmp}/saml_sp.key" | tr -d '\n')"
        if set_app_secrets "$apigw_app" \
            SAML_SP_CERT="$saml_cert_b64" \
            SAML_SP_KEY="$saml_key_b64"; then
            echo "    SAML SP keypair set"
        fi
    else
        echo "    (openssl failed to generate SAML SP keypair; set SAML_SP_CERT/KEY manually)"
    fi
    rm -rf "$saml_tmp"
}

# apigw's credential encryption key and nym_auth seed secret, mounted via
# [[files]] in fly/<profile>/apigw/fly.toml. Each is generated once per
# environment: the seed secret derives every issued ssc.
provision_apigw_nym_auth_secrets() {
    local apigw_app secrets_json value
    apigw_app="$(app_name "apigw")"
    read_app_secrets "$apigw_app" secrets_json
    if grep -q '"CREDENTIAL_ENCRYPTION_KEY"' <<<"$secrets_json"; then
        echo "==> CREDENTIAL_ENCRYPTION_KEY already set for $apigw_app (skipping)"
    else
        echo "==> Provisioning CREDENTIAL_ENCRYPTION_KEY for $apigw_app"
        value="$(openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt | base64 | tr -d '\n')"
        if set_app_secrets "$apigw_app" CREDENTIAL_ENCRYPTION_KEY="$value"; then
            echo "    CREDENTIAL_ENCRYPTION_KEY set"
        fi
    fi
    if grep -q '"NYM_AUTH_SEED"' <<<"$secrets_json"; then
        echo "==> NYM_AUTH_SEED already set for $apigw_app (skipping)"
    else
        echo "==> Provisioning NYM_AUTH_SEED for $apigw_app"
        value="$(openssl rand 32 | basenc --base64url | tr -d '=' | base64 | tr -d '\n')"
        if set_app_secrets "$apigw_app" NYM_AUTH_SEED="$value"; then
            echo "    NYM_AUTH_SEED set"
        fi
    fi
}

# Stage branding data URLs as Fly secrets consumed by the upstream image's
# create_custom_branding_resources.sh at container startup. Uses --stage so no
# extra machine restart — the subsequent `fly deploy` applies them.
push_wallet_frontend_branding_secrets() {
    local app branding_dir
    app="$1"
    branding_dir="$(profile_dir)/wallet-frontend/branding"

    local light dark favicon theme
    light="${branding_dir}/logo_light.png"
    dark="${branding_dir}/logo_dark.png"
    favicon="${branding_dir}/favicon.ico"
    theme="${branding_dir}/theme.json"

    for f in "$light" "$dark" "$favicon" "$theme"; do
        [[ -f "$f" ]] || { echo "    (skip branding: missing $f)"; return 0; }
    done

    local light_b64 dark_b64 favicon_b64 theme_json
    light_b64="$(base64 < "$light" | tr -d '\n')"
    dark_b64="$(base64 < "$dark" | tr -d '\n')"
    favicon_b64="$(base64 < "$favicon" | tr -d '\n')"
    theme_json="$(cat "$theme")"

    echo "    Staging BRANDING_* secrets for $app"
    fly secrets set --stage --app "$app" \
        BRANDING_LOGO_LIGHT="data:image/png;base64,${light_b64}" \
        BRANDING_LOGO_DARK="data:image/png;base64,${dark_b64}" \
        BRANDING_FAVICON="data:image/vnd.microsoft.icon;base64,${favicon_b64}" \
        BRANDING_THEME_JSON="${theme_json}" \
        >/dev/null 2>&1 && echo "    Branding secrets staged" \
        || echo "    (failed to stage branding secrets; continuing)"
}

# Registers the profile's apigw URL as an issuer on the wallet-backend's
# default tenant. wallet-backend has no config-driven issuer bootstrap; without
# this, a fresh deploy shows an empty credentials list in the wallet UI.
# The admin token is rotated each run so we never depend on a value we can't
# read back from Fly. Idempotent: PUT-if-exists so the client_id
# ("fly-wallet") stays in sync with what apigw's static clients map advertises.
register_apigw_issuer_on_wallet_backend() {
    local wb_app apigw_url admin_token proxy_pid body_file
    wb_app="$(app_name wallet-backend)"
    apigw_url="https://$(app_name apigw).fly.dev"

    echo "    Registering ${apigw_url} as issuer on ${wb_app} (default tenant)"

    admin_token="$(openssl rand -hex 32)"
    if ! fly secrets set --app "$wb_app" WALLET_SERVER_ADMIN_TOKEN="$admin_token" >/dev/null 2>&1; then
        echo "    (failed to rotate admin token; skipping issuer registration)"
        return 0
    fi

    fly proxy 18081:8081 --app "$wb_app" >/dev/null 2>&1 &
    proxy_pid=$!

    # Rotating the admin-token secret restarts the backend, and fly's health
    # check has a 10s grace period. Poll until the admin API answers with a
    # 2xx/4xx (i.e. the process is up and TLS-terminating), so a cold start
    # can't silently skip registration by racing an unhealthy backend.
    local ready="" attempt code_probe
    for attempt in $(seq 1 30); do
        code_probe="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 \
            -H "Authorization: Bearer $admin_token" \
            http://127.0.0.1:18081/admin/tenants/default/issuers 2>/dev/null || echo 000)"
        case "$code_probe" in
            2*|4*) ready=1; break ;;
        esac
        sleep 1
    done
    if [[ -z "$ready" ]]; then
        echo "    (wallet-backend admin API did not become ready; skipping issuer registration)"
        stop_proxy "$proxy_pid"
        return 0
    fi
    body_file="/tmp/issuer_reg_body.$$"
    local payload='{"credential_issuer_identifier":"'"$apigw_url"'","client_id":"fly-wallet","visible":true}'

    # The PUT-or-POST choice needs the current issuer list. Without a readable
    # list, a POST would register a duplicate issuer.
    local list_code existing_id method path code
    if ! list_code="$(curl -sS -o "$body_file" -w '%{http_code}' \
        -H "Authorization: Bearer $admin_token" \
        http://127.0.0.1:18081/admin/tenants/default/issuers 2>/dev/null)"; then
        echo "    (listing the issuers failed; skipping issuer registration)"
        stop_proxy "$proxy_pid"
        rm -f "$body_file"
        return 0
    fi
    if [[ "$list_code" != 2?? ]]; then
        echo "    (listing the issuers answered HTTP $list_code; skipping issuer registration)"
        stop_proxy "$proxy_pid"
        rm -f "$body_file"
        return 0
    fi
    # `input` fails on an empty body, and the type check on any JSON other
    # than an object.
    if ! existing_id="$(jq -n -r --arg url "$apigw_url" '
        input
        | if type == "object" then . else error("not an object") end
        | first(.issuers[]? | select(.credential_issuer_identifier == $url) | .id) // ""' \
        "$body_file" 2>/dev/null)"; then
        echo "    (the issuer list is not a JSON object; skipping issuer registration)"
        stop_proxy "$proxy_pid"
        rm -f "$body_file"
        return 0
    fi

    if [[ -n "$existing_id" ]]; then
        method="PUT"
        path="/admin/tenants/default/issuers/$existing_id"
    else
        method="POST"
        path="/admin/tenants/default/issuers"
    fi

    # Retry the admin request itself: the readiness probe above uses the same
    # code path, but the process can briefly go 502 during machine promotion.
    local attempt2
    code="000"
    for attempt2 in 1 2 3; do
        code="$(curl -sS -o "$body_file" -w '%{http_code}' \
            -X "$method" \
            -H "Authorization: Bearer $admin_token" \
            -H 'Content-Type: application/json' \
            -d "$payload" \
            "http://127.0.0.1:18081$path" 2>/dev/null || echo 000)"
        case "$code" in
            200|201) break ;;
        esac
        sleep 2
    done

    case "$code" in
        200) echo "    Issuer updated with client_id=fly-wallet" ;;
        201) echo "    Issuer created with client_id=fly-wallet" ;;
        *)   echo "    Unexpected status $code from admin API (body: $(head -c 200 "$body_file" 2>/dev/null))" ;;
    esac

    stop_proxy "$proxy_pid"
    rm -f "$body_file"
}

# Stops the `fly proxy` with pid $1. A proxy that already exited leaves
# nothing to stop.
stop_proxy() {
    local _pid="$1"
    kill "$_pid" 2>/dev/null || true
    wait "$_pid" 2>/dev/null || true
}

cmd_deploy() {
    require_flyctl
    require_jq
    require_profile_vars
    local profile_root
    profile_root="$(profile_dir)"

    echo "==> Deploying services (prefix=${ENV_PREFIX}, tag=${VC_IMAGE_TAG}, source=${profile_root#$ROOT_DIR/})"
    echo ""
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"

        if ! fly status --app "$app" >/dev/null 2>&1; then
            echo "  [create] $app (auto-creating)"
            fly apps create "$app" --org "$FLY_ORG" || die "Failed to create app: $app"
        fi

        # apigw's SAML SP keypair is provisioned on every deploy, not just on
        # app creation: an upgrade that first introduces the [[files]] mount
        # would otherwise boot without the secrets and crash in
        # tls.LoadX509KeyPair. provision_apigw_saml_sp_keypair is idempotent.
        if [[ "$service" == "apigw" ]]; then
            provision_apigw_saml_sp_keypair
            provision_apigw_nym_auth_secrets
        fi

        if [[ "$service" == "wallet-frontend" ]]; then
            push_wallet_frontend_branding_secrets "$app"
        fi

        echo "  [deploy] $app"
        # Run from repo root so [[files]] local_path values (relative) resolve
        # against the repo layout the way fly deploy expects.
        (
            cd "$ROOT_DIR"
            fly deploy \
                --app "$app" \
                --config "${profile_root}/${service}/fly.toml"
        )

        if [[ "$service" == "wallet-backend" ]]; then
            register_apigw_issuer_on_wallet_backend
        fi

        echo ""
    done
    echo "==> Deployment complete"
}

cmd_secrets() {
    require_profile_vars
    local secrets_file
    secrets_file="$(secrets_file_path)"
    echo "Secrets file for profile '${PROFILE:-custom}' (prefix=${ENV_PREFIX}):"
    echo "  $secrets_file"
    if [[ -f "$secrets_file" ]]; then
        echo "  (exists)"
    else
        echo "  (missing — will be created by 'launch', or copy from secrets.example.yaml)"
    fi
}

cmd_status() {
    require_flyctl
    require_profile_vars
    echo "==> Service status (prefix=${ENV_PREFIX})"
    echo ""
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"
        echo "  [$app]"
        local status_out status_err
        if fly_capture status_out status_err status --app "$app"; then
            [[ -z "$status_out" ]] || printf '%s\n' "$status_out"
        else
            require_app_absent "$app" "reading the status" "$status_err"
            echo "    (not deployed)"
        fi
        echo ""
    done
}

cmd_logs() {
    require_flyctl
    require_profile_vars
    [[ ${#SERVICES[@]} -eq 1 ]] || die "Specify --service for logs"
    local app
    app="$(app_name "${SERVICES[0]}")"
    fly logs --app "$app"
}

cmd_destroy() {
    require_flyctl
    require_profile_vars
    [[ "$CONFIRM" == "yes" ]] || die "Pass --confirm to destroy apps"
    echo "==> Destroying Fly apps (prefix=${ENV_PREFIX})"
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"
        echo "  [destroy] $app"
        local destroy_out destroy_err
        if fly_capture destroy_out destroy_err apps destroy "$app" --yes; then
            [[ -z "$destroy_out" ]] || printf '%s\n' "$destroy_out"
        else
            require_app_absent "$app" "destroying" "$destroy_err"
            echo "    (already gone)"
        fi
    done
}

COMMAND="${1:-}"
shift || true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        --service) TARGET_SERVICE="$2"; shift 2 ;;
        --region)  REGION="$2"; shift 2 ;;
        --env)     ENV_PREFIX="$2"; shift 2 ;;
        --tag)     VC_IMAGE_TAG="$2"; shift 2 ;;
        --org)     FLY_ORG="$2"; shift 2 ;;
        --confirm) CONFIRM="yes"; shift ;;
        -h|--help) usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

apply_profile

if [[ -n "$TARGET_SERVICE" ]]; then
    found=false
    for s in "${SERVICES[@]}"; do
        [[ "$s" == "$TARGET_SERVICE" ]] && found=true
    done
    [[ "$found" == "true" ]] || die "Unknown service: $TARGET_SERVICE (valid: ${SERVICES[*]})"
    SERVICES=("$TARGET_SERVICE")
fi

case "${COMMAND}" in
    launch)  cmd_launch ;;
    deploy)  cmd_deploy ;;
    secrets) cmd_secrets ;;
    status)  cmd_status ;;
    logs)    cmd_logs ;;
    destroy) cmd_destroy ;;
    "")      usage ;;
    *)       die "Unknown command: $COMMAND" ;;
esac
