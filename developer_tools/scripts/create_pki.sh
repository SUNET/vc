#! /bin/sh

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/../pki"

# Create pki directory if it doesn't exist
mkdir -p "${PKI_DIR}"

# The dev stack's services run as the distroless nonroot user and read their
# keys through the ./developer_tools/pki bind mount.
CONTAINER_UID=65532

# On Linux a bind mount keeps host ownership and modes, so the container user
# needs an ACL entry to read its keys. Docker Desktop on macOS serves bind
# mounts with the host user's access.
grant_acl=0
if [ "$(uname -s)" = Linux ]; then
    if ! command -v setfacl >/dev/null 2>&1; then
        echo "setfacl not found: install the acl package; the dev stack reads its keys as uid ${CONTAINER_UID}" >&2
        exit 1
    fi
    grant_acl=1
fi

# The `[ ! -f key ]` guards skip a whole block when its key file exists, so the
# key is removed when the script ends before its block is complete.
generating_key=
remove_unfinished_key() {
    [ -n "$generating_key" ] || return 0
    rm -f "$generating_key"
    echo "removed $generating_key: its generation did not finish" >&2
}
trap remove_unfinished_key EXIT
trap 'exit 1' HUP INT TERM

# Creates empty key file $1 with owner-only access. A default ACL on the
# directory overrides the umask, so an inherited entry is stripped here, before
# any key material exists. `install` creates the file with mode 600, and that
# mode masks an inherited entry from the first moment. The generators write into
# this file and keep its permissions.
create_key_file() {
    generating_key="$1"
    if ! install -m 600 /dev/null "$generating_key" ||
        { [ "$grant_acl" -eq 1 ] && ! setfacl -b "$generating_key"; } ||
        ! chmod 600 "$generating_key"; then
        echo "creating $generating_key with owner-only access failed" >&2
        exit 1
    fi
}

# Sets the access ACL of key file $1 to owner read/write and container user read.
grant_container_read() {
    granted_key="$1"
    [ "$grant_acl" -eq 1 ] || return 0
    if ! setfacl --set "u::rw-,g::---,o::---,u:${CONTAINER_UID}:r--,m::r--" "$granted_key"; then
        echo "granting uid ${CONTAINER_UID} read access to $granted_key failed" >&2
        exit 1
    fi
}

# Runs command $2.. to write key file $1, readable by the owner alone. Call it
# outside any condition: `set -e` must end the script when the command fails.
generate_key() {
    owner_key="$1"
    shift
    create_key_file "$owner_key"
    "$@"
}

# Runs command $2.. to write key file $1, readable by the owner and the container
# user. Call it outside any condition, as generate_key.
generate_container_key() {
    container_key="$1"
    shift
    create_key_file "$container_key"
    grant_container_read "$container_key"
    "$@"
}

# Ends the block of the key generated last, which a later run may skip.
key_block_complete() {
    generating_key=
}

# Writes a P-256 private key in PKCS8 to file $1. It passes through a pipe, so no
# intermediate key reaches the disk.
write_p256_pkcs8() {
    pkcs8_file="$1"
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$pkcs8_file"
}

# Writes $seed to file $1.
write_seed() {
    seed_file="$1"
    printf '%s\n' "${seed}" > "$seed_file"
}

# Service TLS certificates
service_names="apigw verifier registry issuer vc"

# Docker bridge IPs for IP SAN entries (from docker-compose.yaml vc-dev-net)
service_ip() {
    case "$1" in
        apigw)    echo "172.16.50.2"  ;;
        verifier) echo "172.16.50.6"  ;;
        registry) echo "172.16.50.8"  ;;
        issuer)   echo "172.16.50.4"  ;;
        *)        echo "" ;;
    esac
}

# Generate CA key and cert
cat > ca.conf <<EOF
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[dn]
C  = SE
ST = Milky Way
L  = Earth
O  = SUNET
OU = vc Dev
CN = vc_dev_ca
EOF
if [ ! -f "${PKI_DIR}/rootCA.key" ]; then
    echo Creating Root CA

    generate_key "${PKI_DIR}/rootCA.key" openssl genrsa -out "${PKI_DIR}/rootCA.key" 2048
    openssl req -x509 -new -nodes -key "${PKI_DIR}/rootCA.key" -sha256 -days 3650 -out "${PKI_DIR}/rootCA.crt" -config ca.conf \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    key_block_complete
fi

# Create leaf certificates for each service
create_leaf_cert() {
        service_name=${1}

if [ ! -f "${PKI_DIR}/tls_${service_name}.key" ]; then
    echo Creating leaf certificate for ${service_name}

    # Generate config files for openssl
    if [ ! -f ${service_name}.conf ]; then
	cat > ${service_name}.conf <<EOF
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[dn]
C  = SE
ST = Milky Way
L  = Earth
O  = SUNET
OU = vc_dev_rootCA
CN = ${service_name}.vc.docker
EOF
	conf_generated=1
    fi

    if [ ! -f ${service_name}.ext ]; then
	ip=$(service_ip "${service_name}")
	cat > ${service_name}.ext <<EOF
# v3.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${service_name}.vc.docker
EOF
	if [ -n "$ip" ]; then
	    echo "IP.1 = ${ip}" >> ${service_name}.ext
	fi
	ext_generated=1
    fi

    generate_container_key "${PKI_DIR}/tls_${service_name}.key" openssl req -new -sha256 -nodes -out ${service_name}.csr -newkey rsa:2048 -keyout "${PKI_DIR}/tls_${service_name}.key" -config ${service_name}.conf
    openssl x509 -req -in ${service_name}.csr -CA "${PKI_DIR}/rootCA.crt" -CAkey "${PKI_DIR}/rootCA.key" -CAcreateserial -out "${PKI_DIR}/tls_${service_name}.crt" -days 730 -sha256 -extfile ${service_name}.ext

    # Create combined PEM file (cert + CA chain, no private key)
    cat "${PKI_DIR}/tls_${service_name}.crt" "${PKI_DIR}/rootCA.crt" > "${PKI_DIR}/tls_${service_name}_chain.pem"

    # remove temporary files
    rm -f ${service_name}.csr
    if [ $conf_generated -eq 1 ]; then
	rm ${service_name}.conf
    fi
    if [ $ext_generated -eq 1 ]; then
	rm ${service_name}.ext
    fi
    key_block_complete
fi
}

# Generate signing keys with certificates signed by rootCA
generate_signing_keys() {
    # RSA signing key pair (RS256) with certificate
    if [ ! -f "${PKI_DIR}/signing_rsa_private.pem" ]; then
        echo "Generating RSA signing key pair with certificate..."
        
        # Generate RSA private key
        generate_key "${PKI_DIR}/signing_rsa_private.pem" openssl genrsa -out "${PKI_DIR}/signing_rsa_private.pem" 2048
        openssl rsa -in "${PKI_DIR}/signing_rsa_private.pem" -pubout -out "${PKI_DIR}/signing_rsa_public.pem"
        
        # Create CSR config
        cat > signing_rsa.conf <<EOF
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[dn]
C  = SE
ST = Milky Way
L  = Earth
O  = SUNET
OU = vc_dev_signing
CN = vc_dev_signing_rsa
EOF

        # Create extension file for signing certificate
        cat > signing_rsa.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation
subjectAltName = @alt_names

[alt_names]
DNS.1 = vc_dev_signing_rsa
EOF

        # Generate CSR and sign with rootCA
        openssl req -new -key "${PKI_DIR}/signing_rsa_private.pem" -out signing_rsa.csr -config signing_rsa.conf
        openssl x509 -req -in signing_rsa.csr -CA "${PKI_DIR}/rootCA.crt" -CAkey "${PKI_DIR}/rootCA.key" -CAcreateserial -out "${PKI_DIR}/signing_rsa.crt" -days 730 -sha256 -extfile signing_rsa.ext
        
        # Create certificate chain PEM (cert + CA)
        cat "${PKI_DIR}/signing_rsa.crt" "${PKI_DIR}/rootCA.crt" > "${PKI_DIR}/signing_rsa_chain.pem"
        
        # Clean up
        rm -f signing_rsa.csr signing_rsa.conf signing_rsa.ext
        key_block_complete
    fi

    # EC signing key pair (ES256 - P-256 curve) with certificate
    if [ ! -f "${PKI_DIR}/signing_ec_private.pem" ]; then
        echo "Generating EC signing key pair (P-256) with certificate..."
        
        # Generate EC private key in PKCS8 format
        generate_container_key "${PKI_DIR}/signing_ec_private.pem" write_p256_pkcs8 "${PKI_DIR}/signing_ec_private.pem"
        openssl ec -in "${PKI_DIR}/signing_ec_private.pem" -pubout -out "${PKI_DIR}/signing_ec_public.pem"
        
        # Create CSR config
        cat > signing_ec.conf <<EOF
[req]
default_bits       = 256
prompt             = no
default_md         = sha256
distinguished_name = dn

[dn]
C  = SE
ST = Milky Way
L  = Earth
O  = SUNET
OU = vc_dev_signing
CN = vc_dev_signing_ec
EOF

        # Create extension file for signing certificate
        cat > signing_ec.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation
subjectAltName = @alt_names

[alt_names]
DNS.1 = vc_dev_signing_ec
EOF

        # Generate CSR and sign with rootCA
        openssl req -new -key "${PKI_DIR}/signing_ec_private.pem" -out signing_ec.csr -config signing_ec.conf
        openssl x509 -req -in signing_ec.csr -CA "${PKI_DIR}/rootCA.crt" -CAkey "${PKI_DIR}/rootCA.key" -CAcreateserial -out "${PKI_DIR}/signing_ec.crt" -days 730 -sha256 -extfile signing_ec.ext
        
        # Create certificate chain PEM (cert + CA)
        cat "${PKI_DIR}/signing_ec.crt" "${PKI_DIR}/rootCA.crt" > "${PKI_DIR}/signing_ec_chain.pem"
        
        # Clean up
        rm -f signing_ec.csr signing_ec.conf signing_ec.ext
        key_block_complete
    fi

    # EC key-agreement key (P-256) for Credential Request and Response encryption
    if [ ! -f "${PKI_DIR}/credential_encryption.pem" ]; then
        echo "Generating credential encryption key (P-256)..."
        generate_container_key "${PKI_DIR}/credential_encryption.pem" write_p256_pkcs8 "${PKI_DIR}/credential_encryption.pem"
        key_block_complete
    fi

    # Secret of the nym_auth ssc hkdf opening
    if [ ! -f "${PKI_DIR}/nym_auth_seed.key" ]; then
        echo "Generating the nym_auth ssc opening secret..."
        seed=$(openssl rand 32 | basenc --base64url | tr -d '=')
        if [ ${#seed} -ne 43 ]; then
            echo "Generating the nym_auth ssc opening secret failed" >&2
            exit 1
        fi
        generate_container_key "${PKI_DIR}/nym_auth_seed.key" write_seed "${PKI_DIR}/nym_auth_seed.key"
        key_block_complete
    fi
}

for service_name in ${service_names}; do
        create_leaf_cert ${service_name}
done

# Generate signing keys
generate_signing_keys

# Generate client certificate
generate_client_cert() {
    client_name=${1}
    
    if [ ! -f "${PKI_DIR}/client_cert_${client_name}.key" ]; then
        echo "Generating client certificate for ${client_name}..."
        
        # Create CSR config
        cat > ${client_name}.conf <<EOF
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn

[dn]
C  = SE
ST = Milky Way
L  = Earth
O  = SUNET
OU = vc_dev_client
CN = ${client_name}
EOF

        # Create extension file for client certificate
        cat > ${client_name}.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

        # Generate key, CSR and sign with rootCA
        generate_key "${PKI_DIR}/client_cert_${client_name}.key" openssl genrsa -out "${PKI_DIR}/client_cert_${client_name}.key" 2048
        openssl req -new -key "${PKI_DIR}/client_cert_${client_name}.key" -out ${client_name}.csr -config ${client_name}.conf
        openssl x509 -req -in ${client_name}.csr -CA "${PKI_DIR}/rootCA.crt" -CAkey "${PKI_DIR}/rootCA.key" -CAcreateserial -out "${PKI_DIR}/client_cert_${client_name}.crt" -days 730 -sha256 -extfile ${client_name}.ext
        
        # Create combined PEM file (cert + CA chain, no private key)
        cat "${PKI_DIR}/client_cert_${client_name}.crt" "${PKI_DIR}/rootCA.crt" > "${PKI_DIR}/client_cert_${client_name}_chain.pem"
        
        # Clean up
        rm -f ${client_name}.csr ${client_name}.conf ${client_name}.ext
        key_block_complete
    fi
}

# Client certificates
client_names="test-user"

# Generate client certificates
for client_name in ${client_names}; do
    generate_client_cert ${client_name}
done

# Clean up ca.conf
rm -f ca.conf
