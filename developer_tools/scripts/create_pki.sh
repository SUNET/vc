#! /bin/sh

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKI_DIR="${SCRIPT_DIR}/../pki"

# Create pki directory if it doesn't exist
mkdir -p "${PKI_DIR}"

# Service TLS certificates
service_names="apigw verifier ui registry issuer mockas vc"

# Docker bridge IPs for IP SAN entries (from docker-compose.yaml vc-dev-net)
service_ip() {
    case "$1" in
        apigw)    echo "172.16.50.2"  ;;
        verifier) echo "172.16.50.6"  ;;
        ui)       echo "172.16.50.50" ;;
        registry) echo "172.16.50.8"  ;;
        issuer)   echo "172.16.50.4"  ;;
        mockas)   echo "172.16.50.13" ;;
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

    openssl genrsa -out "${PKI_DIR}/rootCA.key" 2048
    openssl req -x509 -new -nodes -key "${PKI_DIR}/rootCA.key" -sha256 -days 3650 -out "${PKI_DIR}/rootCA.crt" -config ca.conf \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
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

    openssl req -new -sha256 -nodes -out ${service_name}.csr -newkey rsa:2048 -keyout "${PKI_DIR}/tls_${service_name}.key" -config ${service_name}.conf
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
fi
}

# Generate signing keys with certificates signed by rootCA
generate_signing_keys() {
    # RSA signing key pair (RS256) with certificate
    if [ ! -f "${PKI_DIR}/signing_rsa_private.pem" ]; then
        echo "Generating RSA signing key pair with certificate..."
        
        # Generate RSA private key
        openssl genrsa -out "${PKI_DIR}/signing_rsa_private.pem" 2048
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
    fi

    # EC signing key pair (ES256 - P-256 curve) with certificate
    if [ ! -f "${PKI_DIR}/signing_ec_private.pem" ]; then
        echo "Generating EC signing key pair (P-256) with certificate..."
        
        # Generate EC private key in PKCS8 format
        openssl ecparam -name prime256v1 -genkey -noout -out signing_ec_private_raw.pem
        openssl pkcs8 -topk8 -nocrypt -in signing_ec_private_raw.pem -out "${PKI_DIR}/signing_ec_private.pem"
        openssl ec -in "${PKI_DIR}/signing_ec_private.pem" -pubout -out "${PKI_DIR}/signing_ec_public.pem"
        rm signing_ec_private_raw.pem
        
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
        openssl genrsa -out "${PKI_DIR}/client_cert_${client_name}.key" 2048
        openssl req -new -key "${PKI_DIR}/client_cert_${client_name}.key" -out ${client_name}.csr -config ${client_name}.conf
        openssl x509 -req -in ${client_name}.csr -CA "${PKI_DIR}/rootCA.crt" -CAkey "${PKI_DIR}/rootCA.key" -CAcreateserial -out "${PKI_DIR}/client_cert_${client_name}.crt" -days 730 -sha256 -extfile ${client_name}.ext
        
        # Create combined PEM file (cert + CA chain, no private key)
        cat "${PKI_DIR}/client_cert_${client_name}.crt" "${PKI_DIR}/rootCA.crt" > "${PKI_DIR}/client_cert_${client_name}_chain.pem"
        
        # Clean up
        rm -f ${client_name}.csr ${client_name}.conf ${client_name}.ext
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
