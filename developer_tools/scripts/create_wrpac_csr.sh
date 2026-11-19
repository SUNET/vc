#! /bin/sh
# Certificate for: identifying the verifier to wallets by signing its OpenID4VP request objects (WRPAC).
#
# Create a private key and a WRPAC-profile CSR (ETSI TS 119 411-8) for
# submission to the WeBuild registry (Raidiam sandbox).
#
# Usage:
#   create_wrpac_csr.sh <name> <dns-name> <org-name> <org-identifier> [country]
#
# Example:
#   create_wrpac_csr.sh verifier sunet-vc-verifier.fly.dev "SUNET" "VATSE-2021005208" SE
#
# Env:
#   KEY_TYPE  ec (default) or rsa. The Raidiam sandbox WRPAC profile rejects RSA despite its docs.
#   CURVE     P-256 (default, the only curve the sandbox profile accepts), P-384 or P-521; only for KEY_TYPE=ec
#   APP_ID    optional, written to organizationalUnitName (Raidiam: must equal application id)
#   CN        optional, defaults to <dns-name>
#   EMAIL     optional contact email SAN; vc's WRPAC check needs a URI or email SAN
#   URI       optional contact URI SAN (default: https://<dns-name>)
#
# Output (gitignored): developer_tools/pki/webuild/<name>-wrpac.{key,csr}

set -e

if [ $# -lt 4 ]; then
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
    exit 1
fi

NAME="$1"
DNS_NAME="$2"
ORG_NAME="$3"
ORG_ID="$4"
COUNTRY="${5:-SE}"
KEY_TYPE="${KEY_TYPE:-ec}"
CURVE="${CURVE:-P-256}"
CN="${CN:-$DNS_NAME}"
URI="${URI:-https://${DNS_NAME}}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../pki/webuild"
KEY_FILE="${OUT_DIR}/${NAME}-wrpac.key"
CSR_FILE="${OUT_DIR}/${NAME}-wrpac.csr"
CNF_FILE="$(mktemp)"
trap 'rm -f "$CNF_FILE"' EXIT

mkdir -p "$OUT_DIR"

if [ -e "$KEY_FILE" ]; then
    echo "Refusing to overwrite existing key: $KEY_FILE" >&2
    exit 1
fi

# The CSR subject must match the registration data in the registry (ASCII only).
{
    echo "[req]"
    echo "prompt             = no"
    echo "default_md         = sha256"
    echo "distinguished_name = dn"
    echo "req_extensions     = ext"
    echo ""
    echo "[dn]"
    echo "countryName            = ${COUNTRY}"
    echo "organizationName       = ${ORG_NAME}"
    echo "organizationIdentifier = ${ORG_ID}"
    [ -n "${APP_ID:-}" ] && echo "organizationalUnitName = ${APP_ID}"
    echo "commonName             = ${CN}"
    echo ""
    echo "[ext]"
    SAN="DNS:${DNS_NAME},URI:${URI}"
    [ -n "${EMAIL:-}" ] && SAN="${SAN},email:${EMAIL}"
    echo "subjectAltName = ${SAN}"
} > "$CNF_FILE"

MD=sha256
case "$KEY_TYPE" in
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY_FILE" ;;
    ec)
        case "$CURVE" in
            P-256) MD=sha256 ;;
            P-384) MD=sha384 ;;
            P-521) MD=sha512 ;;
            *) echo "CURVE must be P-256, P-384 or P-521" >&2; exit 1 ;;
        esac
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$CURVE" -out "$KEY_FILE"
        ;;
    *)   echo "KEY_TYPE must be rsa or ec" >&2; exit 1 ;;
esac
chmod 600 "$KEY_FILE"

openssl req -new -"$MD" -key "$KEY_FILE" -config "$CNF_FILE" -out "$CSR_FILE"

echo "Key: $KEY_FILE"
echo "CSR: $CSR_FILE"
openssl req -in "$CSR_FILE" -noout -subject -verify
