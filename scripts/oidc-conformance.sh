#!/bin/bash
# ==============================================================================
# OpenID Foundation Conformance Suite — Test Runner
# ==============================================================================
#
# Automates conformance testing against the OpenID Foundation Conformance Suite
# for OpenID4VCI (Issuer), OpenID4VP (Verifier), and OIDC OP profiles.
#
# Usage:
#   ./scripts/oidc-conformance.sh setup          — Clone, build & start the suite
#   ./scripts/oidc-conformance.sh test-vci        — Run OpenID4VCI issuer tests
#   ./scripts/oidc-conformance.sh test-vp         — Run OpenID4VP verifier tests
#   ./scripts/oidc-conformance.sh test-oidc       — Run OIDC OP (verifier) tests
#   ./scripts/oidc-conformance.sh test-all        — Run all conformance tests
#   ./scripts/oidc-conformance.sh status          — Show test plan results
#   ./scripts/oidc-conformance.sh stop            — Stop the conformance suite
#   ./scripts/oidc-conformance.sh clean           — Full cleanup
#
# Environment variables:
#   CONFORMANCE_URL     — Conformance suite base URL (default: https://localhost:8443)
#   CONFORMANCE_SUITE_DIR — Where to clone/build the suite (default: /tmp/oidc-conformance-suite)
#   ISSUER_URL          — Issuer/apigw service URL (default: http://apigw.vc.docker:8080)
#   VERIFIER_URL        — Verifier service URL (default: http://verifier.vc.docker:8080)
#   LOG_DIR             — Directory for test logs (default: /tmp/oidc-conformance)
#
# ==============================================================================

set -euo pipefail

# Configuration
CONFORMANCE_URL="${CONFORMANCE_URL:-https://localhost:8443}"
CONFORMANCE_SUITE_DIR="${CONFORMANCE_SUITE_DIR:-/tmp/oidc-conformance-suite}"
ISSUER_URL="${ISSUER_URL:-http://apigw.vc.docker:8080}"
VERIFIER_URL="${VERIFIER_URL:-http://verifier.vc.docker:8080}"
LOG_DIR="${LOG_DIR:-/tmp/oidc-conformance}"
VC_NETWORK="${VC_NETWORK:-vc_vc-dev-net}"
CURL_OPTS="-sk" # silent, allow self-signed TLS

# Docker-in-Docker detection: when running inside a dev container that shares
# the host Docker socket, published ports are on the HOST, not inside this
# container. We detect this and rewrite localhost → Docker host gateway IP.
_resolve_conformance_url() {
    local url="$1"
    # Only rewrite if the URL points to localhost
    if [[ "$url" != *"localhost"* && "$url" != *"127.0.0.1"* ]]; then
        echo "$url"
        return
    fi
    # Check if we're running inside Docker (DinD / devcontainer scenario)
    if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        # Get the default gateway, which is the Docker host from inside a container
        local gw
        gw=$(ip route | awk '/default/ { print $3 }' 2>/dev/null || true)
        if [ -n "$gw" ]; then
            local rewritten="${url//localhost/$gw}"
            rewritten="${rewritten//127.0.0.1/$gw}"
            echo "$rewritten"
            return
        fi
    fi
    echo "$url"
}

# The "internal" URL is what this script uses to talk to the conformance suite.
# It may differ from CONFORMANCE_URL when running inside Docker-in-Docker.
CONFORMANCE_INTERNAL_URL="$(_resolve_conformance_url "$CONFORMANCE_URL")"
API_URL="${CONFORMANCE_INTERNAL_URL}/api"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

mkdir -p "$LOG_DIR"

# ==============================================================================
# Helper Functions
# ==============================================================================

wait_for_url() {
    local url="$1"
    local name="$2"
    local max_attempts="${3:-60}"
    info "Waiting for ${name} at ${url}..."
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl $CURL_OPTS -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null | grep -q '200\|301\|302\|404'; then
            ok "${name} is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        printf "."
        sleep 2
    done
    echo
    err "${name} did not become ready within $((max_attempts * 2))s"
    return 1
}

# Create a test plan via the conformance suite API
# Usage: create_plan <plan_name> <variant_json> <config_json_file>
# Returns: plan ID on the last line
create_plan() {
    local plan_name="$1"
    local variant_json="$2"
    local config_file="$3"

    info "Creating test plan: ${plan_name}" >&2

    # URL-encode the variant JSON for the query parameter
    local variant_encoded
    variant_encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$variant_json")

    local response
    response=$(curl $CURL_OPTS -X POST \
        -H "Content-Type: application/json" \
        -d @"${config_file}" \
        "${API_URL}/plan?planName=${plan_name}&variant=${variant_encoded}" 2>/dev/null)

    local plan_id
    plan_id=$(echo "$response" | jq -r '.id // empty')
    if [ -z "$plan_id" ]; then
        err "Failed to create plan: ${response}"
        return 1
    fi
    ok "Created plan: ${plan_id}" >&2
    echo "$plan_id"
}

# Run all tests in a plan and report results
# Usage: run_plan_tests <plan_id> <plan_name>
run_plan_tests() {
    local plan_id="$1"
    local plan_name="$2"
    local passed=0
    local failed=0
    local warnings=0
    local total=0

    info "Results for plan: ${plan_name} (${plan_id})"
    echo "============================================================"

    local modules
    modules=$(curl $CURL_OPTS -s "${API_URL}/plan/${plan_id}" 2>/dev/null)
    local module_count
    module_count=$(echo "$modules" | jq '.modules | length')

    if [ "$module_count" = "0" ] || [ "$module_count" = "null" ]; then
        warn "No test modules found. Open ${CONFORMANCE_URL} to interact with this plan."
        return 0
    fi

    for i in $(seq 0 $((module_count - 1))); do
        local test_name
        test_name=$(echo "$modules" | jq -r ".modules[$i].testModule")
        local test_id
        test_id=$(echo "$modules" | jq -r ".modules[$i].id // empty")

        total=$((total + 1))

        if [ -n "$test_id" ]; then
            local result
            result=$(curl $CURL_OPTS -s "${API_URL}/info/${test_id}" | jq -r '.result // "NOT_RUN"')
            case "$result" in
                PASSED)   ok "  ${test_name}: PASSED"; passed=$((passed + 1)) ;;
                WARNING)  warn "  ${test_name}: WARNING"; warnings=$((warnings + 1)) ;;
                FAILED)   err "  ${test_name}: FAILED"; failed=$((failed + 1)) ;;
                *)        warn "  ${test_name}: ${result}" ;;
            esac
            # Save individual test log
            curl $CURL_OPTS -s "${API_URL}/log/${test_id}" > "${LOG_DIR}/${test_name}.json" 2>/dev/null || true
        else
            warn "  ${test_name}: NOT STARTED (requires browser interaction)"
        fi
    done

    echo "============================================================"
    echo -e "Results for ${plan_name}:"
    echo -e "  ${GREEN}Passed:${NC}   ${passed}"
    echo -e "  ${RED}Failed:${NC}   ${failed}"
    echo -e "  ${YELLOW}Warnings:${NC} ${warnings}"
    echo -e "  Total:    ${total}"
    echo

    echo "${modules}" | jq '.' > "${LOG_DIR}/${plan_name}-results.json"
    info "Full results saved to ${LOG_DIR}/${plan_name}-results.json"
}

# ==============================================================================
# Test Plan Configuration Generators
# ==============================================================================

gen_vci_config() {
    local output="$1"
    cat > "$output" << EOJSON
{
    "alias": "vc-oid4vci-issuer",
    "description": "VC Project — OpenID4VCI Issuer Conformance Test",
    "server": {
        "discoveryUrl": "${ISSUER_URL}/.well-known/openid-credential-issuer"
    },
    "vci": {
        "credential_issuer_url": "${ISSUER_URL}"
    }
}
EOJSON
    info "Generated VCI config: ${output}"
}

gen_vp_config() {
    local output="$1"
    cat > "$output" << EOJSON
{
    "alias": "vc-oid4vp-verifier",
    "description": "VC Project — OpenID4VP Verifier Conformance Test"
}
EOJSON
    info "Generated VP config: ${output}"
}

gen_oidc_config() {
    local output="$1"
    cat > "$output" << EOJSON
{
    "alias": "vc-oidc-op",
    "description": "VC Project — OIDC OP (Verifier) Conformance Test",
    "server": {
        "discoveryUrl": "${VERIFIER_URL}/.well-known/openid-configuration"
    }
}
EOJSON
    info "Generated OIDC OP config: ${output}"
}

# ==============================================================================
# Commands
# ==============================================================================

cmd_setup() {
    info "=== Setting up OpenID Conformance Suite ==="

    # This dev container uses Docker-out-of-Docker (host Docker socket).
    # Bind mounts reference the HOST filesystem, so we use Docker volumes
    # and build everything inside Docker containers.

    local img_name="oidc-conformance-suite:local"
    local vol_m2="oidc-conformance-m2"

    # Check if image already exists
    if docker image inspect "$img_name" &>/dev/null; then
        ok "Conformance suite image already built"
    else
        info "Building conformance suite Docker image (first run takes ~5-10 min)..."

        # Create a maven cache volume to speed up rebuilds
        docker volume create "$vol_m2" >/dev/null 2>&1 || true

        # Build everything in a single multi-stage Docker build
        # We pipe the Dockerfile via stdin and use the git repo as context
        docker build --tag "$img_name" \
            --build-arg MAVEN_CACHE_VOL="$vol_m2" \
            -f - https://gitlab.com/openid/conformance-suite.git << 'DOCKERFILE'
# Stage 1: Build the JAR
FROM maven:3-eclipse-temurin-17 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN git init && git config user.email "build@local" && git config user.name "build" && git add -A && git commit -m "build" --allow-empty
RUN mvn -B clean package -DskipTests=true

# Stage 2: Build nginx with self-signed cert
FROM debian:bookworm-slim AS nginx-builder
RUN apt-get update && apt-get install -y nginx openssl && \
    openssl req -x509 -nodes -newkey rsa:2048 \
      -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
      -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
      -subj '/CN=localhost' -days 3650
COPY nginx/nginx.conf /etc/nginx/nginx.conf.template
# Patch nginx.conf for single-container mode:
# - proxy to localhost instead of "server" hostname
# - use the self-signed cert paths
# - use local resolver
RUN sed -e 's|http://server:8080|http://127.0.0.1:8080|g' \
    -e 's|http://server-mtls:8080|http://127.0.0.1:8080|g' \
    -e 's|resolver 127.0.0.11 ipv6=off;|resolver 127.0.0.1 ipv6=off valid=1s;|g' \
    -e 's|ssl_certificate .*nginx-selfsigned.crt;|ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;|g' \
    -e 's|ssl_certificate_key .*nginx-selfsigned.key;|ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;|g' \
    /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf.patched

# Stage 3: Final runtime image
FROM eclipse-temurin:17-jre

# Install nginx
RUN apt-get update && apt-get install -y --no-install-recommends nginx openssl curl && \
    rm -rf /var/lib/apt/lists/*

# Copy SSL certs from nginx builder
COPY --from=nginx-builder /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/private/
COPY --from=nginx-builder /etc/ssl/certs/ssl-cert-snakeoil.pem /etc/ssl/certs/

# Copy patched nginx config (single-container mode: proxy to localhost)
COPY --from=nginx-builder /etc/nginx/nginx.conf.patched /etc/nginx/nginx.conf

# Copy the built JAR
COPY --from=builder /src/target/fapi-test-suite.jar /server/fapi-test-suite.jar

# Startup script
RUN cat > /start.sh << 'STARTEOF'
#!/bin/bash
set -e
# Start nginx in background (single-container: proxies to localhost:8080)
nginx -g 'daemon on;' || echo "WARN: nginx failed to start"
# Start the Java server (listens on 8080, nginx TLS on 8443)
exec java \
  -jar /server/fapi-test-suite.jar \
  -Djdk.tls.maxHandshakeMessageSize=65536 \
  --spring.data.mongodb.host=${MONGODB_HOST:-mongodb} \
  --fintechlabs.base_url=${BASE_URL:-https://localhost:8443} \
  --fintechlabs.devmode=true \
  --fintechlabs.startredir=true
STARTEOF
RUN chmod +x /start.sh

EXPOSE 8443
CMD ["/start.sh"]
DOCKERFILE

        ok "Image built successfully"
    fi

    # Determine VC network
    local network_args=""
    if docker network inspect "${VC_NETWORK}" &>/dev/null; then
        network_args="--network ${VC_NETWORK}"
        info "Will connect to VC dev network: ${VC_NETWORK}"
    elif docker network inspect "vc-dev-net" &>/dev/null; then
        network_args="--network vc-dev-net"
        info "Will connect to VC dev network: vc-dev-net"
    else
        warn "VC dev network not found. Suite will start but can't reach VC services."
        warn "Run 'make start' to create the VC dev stack."
    fi

    # Start MongoDB
    info "Starting MongoDB for conformance suite..."
    docker rm -f oidc-conformance-mongo 2>/dev/null || true
    docker run -d \
        --name oidc-conformance-mongo \
        --hostname conformance-mongo \
        -v oidc-conformance-mongo-data:/data/db \
        ${network_args} \
        mongo:6.0.13 >/dev/null

    # Start the conformance suite
    info "Starting conformance suite..."
    docker rm -f oidc-conformance-server 2>/dev/null || true
    docker run -d \
        --name oidc-conformance-server \
        --hostname conformance.vc.docker \
        --link oidc-conformance-mongo:mongodb \
        -p 8443:8443 \
        -e "BASE_URL=${CONFORMANCE_URL}" \
        -e "MONGODB_HOST=mongodb" \
        ${network_args} \
        "$img_name" >/dev/null

    wait_for_url "${CONFORMANCE_INTERNAL_URL}" "Conformance suite" 90

    ok "Conformance suite is running"
    echo
    info "Web UI: ${CONFORMANCE_URL}"
    if [ "${CONFORMANCE_INTERNAL_URL}" != "${CONFORMANCE_URL}" ]; then
        info "API:    ${CONFORMANCE_INTERNAL_URL}/api (internal / DinD)"
    else
        info "API:    ${API_URL}"
    fi
    info ""
    info "Note: Accept the self-signed certificate in your browser."
}

cmd_stop() {
    info "Stopping OpenID Conformance Suite..."
    docker stop oidc-conformance-server oidc-conformance-mongo 2>/dev/null || true
    docker rm oidc-conformance-server oidc-conformance-mongo 2>/dev/null || true
    ok "Conformance suite stopped"
}

cmd_clean() {
    info "Cleaning up..."
    cmd_stop 2>/dev/null || true
    rm -rf "${LOG_DIR}"
    # Remove Docker volumes and image
    docker volume rm oidc-conformance-mongo-data oidc-conformance-m2 2>/dev/null || true
    info "To also remove the built image (~1GB), run:"
    info "  docker rmi oidc-conformance-suite:local"
    ok "Cleaned up"
}

cmd_test_vci() {
    info "=== OpenID4VCI Issuer Conformance Test ==="
    wait_for_url "${CONFORMANCE_INTERNAL_URL}" "Conformance suite" 5 || {
        err "Conformance suite not running. Run: make oidc-conformance-setup"
        exit 1
    }

    local config_file="${LOG_DIR}/vci-plan-config.json"
    gen_vci_config "$config_file"

    local variant_json='{"vci_profile":"plain_vci","client_auth_type":"private_key_jwt","sender_constrain":"dpop","credential_format":"sd_jwt_vc","authorization_request_type":"simple","fapi_request_method":"unsigned","vci_grant_type":"authorization_code","vci_authorization_code_flow_variant":"wallet_initiated","vci_credential_encryption":"plain"}'

    local plan_id
    plan_id=$(create_plan "oid4vci-1_0-issuer-test-plan" "$variant_json" "$config_file")
    echo "$plan_id" > "${LOG_DIR}/vci-plan-id.txt"

    echo
    info "Test plan created: ${plan_id}"
    info ""
    info "The OpenID4VCI conformance tests will act as a wallet client"
    info "against your issuer at ${ISSUER_URL}."
    info ""
    info "Next steps:"
    info "  1. Open: ${CONFORMANCE_URL}"
    info "  2. Select the plan: ${plan_id}"
    info "  3. Run the test modules"
    info "  4. Check results: make oidc-conformance-status"
}

cmd_test_vp() {
    info "=== OpenID4VP Verifier Conformance Test ==="
    wait_for_url "${CONFORMANCE_INTERNAL_URL}" "Conformance suite" 5 || {
        err "Conformance suite not running. Run: make oidc-conformance-setup"
        exit 1
    }

    local config_file="${LOG_DIR}/vp-plan-config.json"
    gen_vp_config "$config_file"

    local variant_json='{"credential_format":"sd_jwt_vc","response_mode":"direct_post","request_method":"request_uri_signed","vp_profile":"plain_vp","client_id_prefix":"x509_san_dns"}'

    local plan_id
    plan_id=$(create_plan "oid4vp-1final-verifier-test-plan" "$variant_json" "$config_file")
    echo "$plan_id" > "${LOG_DIR}/vp-plan-id.txt"

    echo
    info "Test plan created: ${plan_id}"
    info ""
    info "The OpenID4VP conformance tests verify the verifier's ability to"
    info "request and validate verifiable presentations."
    info ""
    info "Next steps:"
    info "  1. Open: ${CONFORMANCE_URL}"
    info "  2. Select the plan: ${plan_id}"
    info "  3. Run the test modules"
    info "  4. Check results: make oidc-conformance-status"
}

cmd_test_oidc() {
    info "=== OIDC OP (Verifier) Conformance Test ==="
    wait_for_url "${CONFORMANCE_INTERNAL_URL}" "Conformance suite" 5 || {
        err "Conformance suite not running. Run: make oidc-conformance-setup"
        exit 1
    }

    local config_file="${LOG_DIR}/oidc-plan-config.json"
    gen_oidc_config "$config_file"

    local variant_json='{"server_metadata":"discovery","client_registration":"dynamic_client"}'

    local plan_id
    plan_id=$(create_plan "oidcc-basic-certification-test-plan" "$variant_json" "$config_file")
    echo "$plan_id" > "${LOG_DIR}/oidc-plan-id.txt"

    echo
    info "Test plan created: ${plan_id}"
    info ""
    info "The OIDC OP conformance tests verify the verifier's OpenID Provider"
    info "implementation (discovery, authorization, token, userinfo)."
    info ""
    info "Next steps:"
    info "  1. Open: ${CONFORMANCE_URL}"
    info "  2. Select the plan: ${plan_id}"
    info "  3. Run test modules (some need browser interaction)"
    info "  4. Check results: make oidc-conformance-status"
}

cmd_test_all() {
    cmd_test_vci
    echo
    cmd_test_vp
    echo
    cmd_test_oidc
}

cmd_status() {
    info "=== OpenID Conformance Test Status ==="
    echo

    local found=0
    for profile in vci vp oidc; do
        local plan_file="${LOG_DIR}/${profile}-plan-id.txt"
        if [ -f "$plan_file" ]; then
            found=1
            local plan_id
            plan_id=$(cat "$plan_file")
            local plan_name
            case "$profile" in
                vci)  plan_name="OpenID4VCI Issuer" ;;
                vp)   plan_name="OpenID4VP Verifier" ;;
                oidc) plan_name="OIDC OP" ;;
            esac
            run_plan_tests "$plan_id" "$plan_name"
        fi
    done

    if [ $found -eq 0 ]; then
        warn "No test plans found. Run one of:"
        warn "  make oidc-conformance-test-vci"
        warn "  make oidc-conformance-test-vp"
        warn "  make oidc-conformance-test-oidc"
    fi
}

cmd_help() {
    echo "OpenID Foundation Conformance Suite — Test Runner"
    echo
    echo "Usage: $0 <command>"
    echo
    echo "Commands:"
    echo "  setup       Clone, build & start the conformance suite"
    echo "  stop        Stop the conformance suite"
    echo "  clean       Stop + remove logs (prompts for suite removal)"
    echo "  test-vci    Create OpenID4VCI issuer test plan"
    echo "  test-vp     Create OpenID4VP verifier test plan"
    echo "  test-oidc   Create OIDC OP test plan"
    echo "  test-all    Create all test plans"
    echo "  status      Show test plan results"
    echo "  help        Show this help message"
    echo
    echo "Environment variables:"
    echo "  CONFORMANCE_URL       Suite URL (default: https://localhost:8443)"
    echo "  CONFORMANCE_SUITE_DIR Clone dir (default: /tmp/oidc-conformance-suite)"
    echo "  ISSUER_URL            Issuer URL (default: http://apigw.vc.docker:8080)"
    echo "  VERIFIER_URL          Verifier URL (default: http://verifier.vc.docker:8080)"
    echo "  VC_NETWORK            Docker network (default: vc_vc-dev-net)"
    echo "  LOG_DIR               Log dir (default: /tmp/oidc-conformance)"
}

# ==============================================================================
# Main
# ==============================================================================

command="${1:-help}"
case "$command" in
    setup)      cmd_setup ;;
    stop)       cmd_stop ;;
    clean)      cmd_clean ;;
    test-vci)   cmd_test_vci ;;
    test-vp)    cmd_test_vp ;;
    test-oidc)  cmd_test_oidc ;;
    test-all)   cmd_test_all ;;
    status)     cmd_status ;;
    help)       cmd_help ;;
    *)
        err "Unknown command: ${command}"
        cmd_help
        exit 1
        ;;
esac
