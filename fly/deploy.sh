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

usage() {
    sed -n '2,/^$/s/^# //p' "$0"
    exit 1
}

die() { echo "Error: $*" >&2; exit 1; }

require_flyctl() {
    command -v fly >/dev/null 2>&1 || die "flyctl not found. Install: https://fly.io/docs/flyctl/install/"
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

cmd_launch() {
    require_flyctl
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
    local ips_json
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"
        ips_json="$(fly ips list --app "$app" --json 2>/dev/null || echo '[]')"
        if ! echo "$ips_json" | grep -qE '"Type":\s*"(shared_v4|v4)"'; then
            echo "  [ipv4] $app"
            fly ips allocate-v4 --shared --app "$app" 2>/dev/null || echo "    (failed; check manually)"
        fi
        if ! echo "$ips_json" | grep -q '"Type":\s*"v6"'; then
            echo "  [ipv6] $app"
            fly ips allocate-v6 --app "$app" 2>/dev/null || echo "    (failed; check manually)"
        fi
    done
    echo ""

    local secrets_file
    secrets_file="$(secrets_file_path)"

    local mongo_app mongo_pass mongo_user mongo_uri
    mongo_app="$(app_name "mongodb")"
    mongo_user="admin"

    # Idempotent: if MongoDB already has creds, keep them. Rotating
    # MONGO_INITDB_ROOT_PASSWORD after the data dir is initialised does NOT
    # change the on-disk user — it desyncs the whole stack (apigw/wallet-backend
    # end up with a URI that no longer authenticates). Only generate + set on
    # first launch.
    if fly secrets list --app "$mongo_app" --json 2>/dev/null | grep -q '"MONGO_INITDB_ROOT_PASSWORD"'; then
        echo "==> MongoDB secrets already set for $mongo_app (skipping)"
        mongo_pass=""
        mongo_uri=""
    else
        # hex, not base64: password is embedded in a URI, must be URL-safe.
        mongo_pass="$(openssl rand -hex 24)"
        mongo_uri="mongodb://${mongo_user}:${mongo_pass}@${mongo_app}.internal:27017/?authSource=admin"

        echo "==> Setting MongoDB secrets for $mongo_app"
        fly secrets set --app "$mongo_app" \
            MONGO_INITDB_ROOT_USERNAME="$mongo_user" \
            MONGO_INITDB_ROOT_PASSWORD="$mongo_pass" \
            2>/dev/null && echo "    MongoDB secrets set" || echo "    (failed to set MongoDB secrets)"

        if [[ ! -f "$secrets_file" ]]; then
            cp "${ROOT_DIR}/secrets.example.yaml" "$secrets_file"
            echo "    Created $secrets_file from secrets.example.yaml"
        fi
        sed -i "s|uri:.*|uri: \"${mongo_uri}\"|" "$secrets_file"
        echo "    Updated $secrets_file with MongoDB URI"
    fi

    local oidc_app apigw_client_secret demo_user_password
    oidc_app="$(app_name "oidc")"

    # Idempotent: Keycloak's realm import runs once on first boot and stores
    # the client_secret + user password hashes in its H2 DB. Rotating these
    # env vars later does NOT change what's in the DB — it desyncs apigw's
    # secrets file from Keycloak. Only set on first launch.
    if fly secrets list --app "$oidc_app" --json 2>/dev/null | grep -q '"APIGW_OIDC_CLIENT_SECRET"'; then
        echo "==> OIDC secrets already set for $oidc_app (skipping)"
    else
        apigw_client_secret="$(openssl rand -hex 24)"
        # 4 chars for live demos: 3 lowercase letters + 1 trailing digit.
        demo_user_password="$(LC_ALL=C awk 'BEGIN{srand();s="";for(i=0;i<3;i++)s=s substr("abcdefghjkmnpqrstuvwxyz",int(rand()*23)+1,1);print s int(rand()*10)}')"

        echo "==> Setting OIDC secrets for $oidc_app"
        fly secrets set --app "$oidc_app" \
            APIGW_OIDC_CLIENT_SECRET="$apigw_client_secret" \
            DEMO_USER_PASSWORD="$demo_user_password" \
            2>/dev/null && echo "    OIDC secrets set" || echo "    (failed to set OIDC secrets)"

        if command -v yq >/dev/null 2>&1; then
            yq -i ".apigw.auth_providers.oidc.registration.preconfigured.client_secret = \"$apigw_client_secret\"" "$secrets_file"
            echo "    Updated $secrets_file with apigw OIDC client_secret"
        else
            echo "    WARNING: yq not found; set apigw.auth_providers.oidc.registration.preconfigured.client_secret in $secrets_file manually to: $apigw_client_secret"
        fi
        echo "    Demo user password (Keycloak realm users): $demo_user_password"
    fi

    local wallet_backend_app as_key_pem as_key_b64
    wallet_backend_app="$(app_name "wallet-backend")"
    echo "==> Setting AS signing key for $wallet_backend_app"
    if fly secrets list --app "$wallet_backend_app" --json 2>/dev/null | grep -q '"AS_SIGNING_KEY_PEM"'; then
        echo "    (AS_SIGNING_KEY_PEM already set, leaving in place)"
    else
        as_key_pem="$(openssl ecparam -name prime256v1 -genkey -noout)"
        as_key_b64="$(printf '%s' "$as_key_pem" | base64 | tr -d '\n')"
        fly secrets set --app "$wallet_backend_app" \
            AS_SIGNING_KEY_PEM="$as_key_b64" \
            2>/dev/null && echo "    AS signing key set" || echo "    (failed to set AS_SIGNING_KEY_PEM; app missing?)"
    fi

    # Idempotent: only push the URI if we generated a fresh one above.
    if [[ -n "$mongo_uri" ]]; then
        echo "==> Setting Mongo URI for $wallet_backend_app"
        fly secrets set --app "$wallet_backend_app" \
            WALLET_STORAGE_MONGODB_URI="$mongo_uri" \
            2>/dev/null && echo "    Mongo URI set" || echo "    (failed to set WALLET_STORAGE_MONGODB_URI; app missing?)"
    else
        echo "==> Mongo URI on $wallet_backend_app left in place (MongoDB creds unchanged)"
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
            local svc_app
            svc_app="$(app_name "$svc")"
            echo "==> Setting signing secrets for $svc_app"
            if fly secrets list --app "$svc_app" --json 2>/dev/null | grep -q '"SIGNING_EC_PRIVATE_KEY"'; then
                echo "    (SIGNING_EC_PRIVATE_KEY already set, leaving in place)"
            else
                fly secrets set --app "$svc_app" \
                    SIGNING_EC_PRIVATE_KEY="$signing_key_b64" \
                    SIGNING_EC_CHAIN="$signing_chain_b64" \
                    2>/dev/null && echo "    Signing secrets set" || echo "    (failed to set signing secrets; app missing?)"
            fi
        done
    else
        echo "WARNING: no ${pki_dir}/signing_ec_{private,chain}.pem found;"
        echo "         set SIGNING_EC_PRIVATE_KEY / SIGNING_EC_CHAIN manually on"
        echo "         apigw/issuer/verifier/registry, or run make dev-pki first."
    fi

    echo ""
    echo "==> Apps created. Next: ./fly/deploy.sh deploy --profile ${PROFILE:-dev}"
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
    sleep 3

    body_file="/tmp/issuer_reg_body.$$"
    local payload='{"credential_issuer_identifier":"'"$apigw_url"'","client_id":"fly-wallet","visible":true}'

    local list existing_id method path code
    list="$(curl -sS -H "Authorization: Bearer $admin_token" \
        http://127.0.0.1:18081/admin/tenants/default/issuers 2>/dev/null || echo '{}')"
    existing_id="$(printf '%s' "$list" | jq -r --arg url "$apigw_url" \
        '.issuers[]? | select(.credential_issuer_identifier == $url) | .id' 2>/dev/null | head -n 1)"

    if [[ -n "$existing_id" ]]; then
        method="PUT"
        path="/admin/tenants/default/issuers/$existing_id"
    else
        method="POST"
        path="/admin/tenants/default/issuers"
    fi

    code="$(curl -sS -o "$body_file" -w '%{http_code}' \
        -X "$method" \
        -H "Authorization: Bearer $admin_token" \
        -H 'Content-Type: application/json' \
        -d "$payload" \
        "http://127.0.0.1:18081$path" 2>/dev/null || echo 000)"

    case "$code" in
        200|201) echo "    Issuer ${method,,}ed with client_id=fly-wallet" ;;
        *)       echo "    Unexpected status $code from admin API (body: $(head -c 200 "$body_file" 2>/dev/null))" ;;
    esac

    kill "$proxy_pid" 2>/dev/null
    wait "$proxy_pid" 2>/dev/null || true
    rm -f "$body_file"
}

cmd_deploy() {
    require_flyctl
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
        fly status --app "$app" 2>/dev/null || echo "    (not deployed)"
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
        fly apps destroy "$app" --yes 2>/dev/null || echo "    (already gone)"
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
