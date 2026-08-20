#!/usr/bin/env bash
# Fly.io deployment helper for VC services.
# Usage:
#   ./fly/deploy.sh [command] [options]
#
# Commands:
#   launch     - Create Fly apps for all services (first time only)
#   deploy     - Deploy all services (or specify --service <name>)
#   secrets    - Set secrets for a service from a YAML file
#   status     - Show status of all services
#   logs       - Tail logs for a service
#   destroy    - Destroy all Fly apps (requires --confirm)
#
# Options:
#   --service <name>   Target a specific service (apigw, issuer, verifier, registry)
#   --region <code>    Override primary region (default: arn)
#   --env <name>       Environment name prefix (default: vc)
#   --confirm          Required for destructive operations

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure flyctl is on PATH
export FLYCTL_INSTALL="${FLYCTL_INSTALL:-$HOME/.fly}"
export PATH="$FLYCTL_INSTALL/bin:$PATH"

# Defaults
SERVICES=(mongodb oidc go-trust apigw issuer verifier registry wallet-backend wallet-frontend)
REGION="${FLY_REGION:-arn}"
ENV_PREFIX="${FLY_ENV_PREFIX:-sunet-vc}"
FLY_ORG="${FLY_ORG:-sirosfoundation}"
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

app_name() {
    local service="$1"
    echo "${ENV_PREFIX}-${service}"
}

fly_dir() {
    local service="$1"
    echo "$SCRIPT_DIR/$service"
}

# Parse arguments
COMMAND="${1:-}"
shift || true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --service) TARGET_SERVICE="$2"; shift 2 ;;
        --region)  REGION="$2"; shift 2 ;;
        --env)     ENV_PREFIX="$2"; shift 2 ;;
        --org)     FLY_ORG="$2"; shift 2 ;;
        --confirm) CONFIRM="yes"; shift ;;
        -h|--help) usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

# Filter services if --service specified
if [[ -n "$TARGET_SERVICE" ]]; then
    found=false
    for s in "${SERVICES[@]}"; do
        [[ "$s" == "$TARGET_SERVICE" ]] && found=true
    done
    [[ "$found" == "true" ]] || die "Unknown service: $TARGET_SERVICE (valid: ${SERVICES[*]})"
    SERVICES=("$TARGET_SERVICE")
fi

cmd_launch() {
    require_flyctl
    echo "==> Launching Fly apps in region: $REGION"
    echo ""
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"
        local dir
        dir="$(fly_dir "$service")"

        if fly apps list --json 2>/dev/null | grep -q "\"$app\""; then
            echo "  [skip] $app already exists"
            continue
        fi

        echo "  [create] $app"
        fly apps create "$app" --org "$FLY_ORG" || die "Failed to create app: $app"
        echo "    Created app: $app"
    done
    echo ""

    # Generate MongoDB password and set secrets
    local mongo_app mongo_pass mongo_user mongo_uri
    mongo_app="$(app_name "mongodb")"
    mongo_user="admin"
    mongo_pass="$(openssl rand -base64 24)"
    mongo_uri="mongodb://${mongo_user}:${mongo_pass}@${mongo_app}.internal:27017/?authSource=admin"

    echo "==> Setting MongoDB secrets for $mongo_app"
    fly secrets set --app "$mongo_app" \
        MONGO_INITDB_ROOT_USERNAME="$mongo_user" \
        MONGO_INITDB_ROOT_PASSWORD="$mongo_pass" \
        2>/dev/null && echo "    MongoDB secrets set" || echo "    (secrets already set or app missing)"

    # Update secrets.yaml with the generated mongo URI
    local secrets_file="${ROOT_DIR}/secrets.yaml"
    if [[ ! -f "$secrets_file" ]]; then
        cp "${ROOT_DIR}/secrets.example.yaml" "$secrets_file"
    fi
    sed -i "s|uri:.*|uri: \"${mongo_uri}\"|" "$secrets_file"
    echo "    Updated $secrets_file with MongoDB URI"

    echo ""
    echo "==> Apps created. Next: ./fly/deploy.sh deploy"
}

cmd_deploy() {
    require_flyctl
    echo "==> Deploying services"
    echo ""
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"
        local dir
        dir="$(fly_dir "$service")"

        # Create app if it doesn't exist
        if ! fly apps list --json 2>/dev/null | grep -q "\"$app\""; then
            echo "  [create] $app (auto-creating)"
            fly apps create "$app" --org "$FLY_ORG" || die "Failed to create app: $app"
        fi

        echo "  [deploy] $app"
        fly deploy \
            --app "$app" \
            --config "$dir/fly.toml"
        echo ""
    done
    echo "==> Deployment complete"
}

cmd_secrets() {
    require_flyctl
    local secrets_file="${ROOT_DIR}/secrets.yaml"
    [[ -f "$secrets_file" ]] || secrets_file="${ROOT_DIR}/secrets.example.yaml"
    [[ -f "$secrets_file" ]] || die "No secrets.yaml found. Copy secrets.example.yaml to secrets.yaml"

    echo "==> Setting secrets from: $secrets_file"
    echo ""
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"
        echo "  [secrets] $app"
        echo "    Set secrets with: fly secrets set --app $app KEY=value"
        echo "    Or import: fly secrets import --app $app < secrets.env"
    done
    echo ""
    echo "Common secrets to set:"
    echo "  MONGO_URI          - MongoDB connection string"
    echo "  SIGNING_KEY        - Base64-encoded signing private key"
    echo "  TLS_CERT           - Base64-encoded TLS certificate"
    echo "  TLS_KEY            - Base64-encoded TLS private key"
}

cmd_status() {
    require_flyctl
    echo "==> Service status"
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
    [[ ${#SERVICES[@]} -eq 1 ]] || die "Specify --service for logs"
    local app
    app="$(app_name "${SERVICES[0]}")"
    fly logs --app "$app"
}

cmd_destroy() {
    require_flyctl
    [[ "$CONFIRM" == "yes" ]] || die "Pass --confirm to destroy apps"

    echo "==> Destroying Fly apps"
    for service in "${SERVICES[@]}"; do
        local app
        app="$(app_name "$service")"
        echo "  [destroy] $app"
        fly apps destroy "$app" --yes 2>/dev/null || echo "    (already gone)"
    done
}

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
