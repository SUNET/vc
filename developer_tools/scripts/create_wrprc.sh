#! /bin/sh
# Certificate for: anchoring the issuer's entry in a WE BUILD trusted list (e.g. Pub-EAA Providers).
#
# Create a private key and a CSR for onboarding to a trusted list on the
# IDunion console (https://console.dev.idunion.info), per its direct
# onboarding guide: EC P-256 key, subject C/ST/L/O/CN.
#
# Usage:
#   create_wrprc.sh <name> <org-name> <common-name> [country]
#
# Example:
#   STATE=Stockholm LOCALITY=Stockholm \
#     create_wrprc.sh issuer "SUNET" sunet-vc-apigw.fly.dev SE
#
# Env:
#   STATE     state or region (default: Stockholm)
#   LOCALITY  city (default: Stockholm)
#
# <org-name> must match the "Organisation Name" you enter in the console form.
# Output (gitignored): developer_tools/pki/webuild/<name>-wrprc-idunion.{key,csr}

set -e

if [ $# -lt 3 ]; then
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
    exit 1
fi

NAME="$1"
ORG_NAME="$2"
CN="$3"
COUNTRY="${4:-SE}"
STATE="${STATE:-Stockholm}"
LOCALITY="${LOCALITY:-Stockholm}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${SCRIPT_DIR}/../pki/webuild"
OUT_DIR="$(cd "${SCRIPT_DIR}/../pki/webuild" && pwd)"
KEY_FILE="${OUT_DIR}/${NAME}-wrprc-idunion.key"
CSR_FILE="${OUT_DIR}/${NAME}-wrprc-idunion.csr"

if [ -e "$KEY_FILE" ]; then
    echo "Refusing to overwrite existing key: $KEY_FILE" >&2
    exit 1
fi

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$KEY_FILE"
chmod 600 "$KEY_FILE"

openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORG_NAME}/CN=${CN}"

echo "Key: $KEY_FILE"
echo "CSR: $CSR_FILE"
openssl req -in "$CSR_FILE" -noout -subject -verify
