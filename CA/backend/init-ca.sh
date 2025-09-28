#!/bin/bash
set -e

ROOT_DIR="ca/root"
INTER_DIR="ca/intermediate"
mkdir -p $ROOT_DIR/{certs,crl,newcerts,private} $INTER_DIR/{certs,crl,newcerts,private}

touch $ROOT_DIR/index.txt
echo 1000 > $ROOT_DIR/serial
echo 1000 > $ROOT_DIR/crlnumber

touch $INTER_DIR/index.txt
echo 1000 > $INTER_DIR/serial
echo 1000 > $INTER_DIR/crlnumber

echo "[+] Génération CA Root"
openssl genrsa -out $ROOT_DIR/private/rootCA.key 4096

openssl req -x509 -new -nodes -key $ROOT_DIR/private/rootCA.key -sha256 -days 3650 \
  -out $ROOT_DIR/certs/rootCA.pem \
  -subj "/C=BE/ST=Belgique/L=Namur/O=CA Root/CN=CA Root" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

echo "[+] Génération CA Intermédiaire"
openssl genrsa -out $INTER_DIR/private/interCA.key 4096

openssl req -new -key $INTER_DIR/private/interCA.key -out $INTER_DIR/interCA.csr \
  -subj "/C=BE/ST=Belgique/L=Namur/O=CA Inter/CN=Intermediate CA"

openssl x509 -req -in $INTER_DIR/interCA.csr \
  -CA $ROOT_DIR/certs/rootCA.pem -CAkey $ROOT_DIR/private/rootCA.key -CAcreateserial \
  -out $INTER_DIR/certs/interCA.pem -days 1825 -sha256 \
  -extfile <(cat <<EOF
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
)

cat > $ROOT_DIR/openssl-root.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $ROOT_DIR
database          = $ROOT_DIR/index.txt
new_certs_dir     = $ROOT_DIR/newcerts
certificate       = $ROOT_DIR/certs/rootCA.pem
private_key       = $ROOT_DIR/private/rootCA.key
serial            = $ROOT_DIR/serial
crlnumber         = $ROOT_DIR/crlnumber
crl               = $ROOT_DIR/crl/rootCA.crl
default_days      = 3650
default_crl_days  = 30
default_md        = sha256
policy            = policy_any
x509_extensions   = v3_ca

[ policy_any ]
countryName = optional
stateOrProvinceName = optional
organizationName = optional
commonName = optional
emailAddress = optional

[ v3_ca ]
basicConstraints = critical,CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ crl_ext ]
authorityKeyIdentifier=keyid:always
EOF

cat > $INTER_DIR/openssl.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $INTER_DIR
database          = $INTER_DIR/index.txt
new_certs_dir     = $INTER_DIR/newcerts
certificate       = $INTER_DIR/certs/interCA.pem
private_key       = $INTER_DIR/private/interCA.key
serial            = $INTER_DIR/serial
crlnumber         = $INTER_DIR/crlnumber
crl               = $INTER_DIR/crl/interCA.crl
default_days      = 365
default_crl_days  = 30
default_md        = sha256
policy            = policy_any
x509_extensions   = usr_cert

[ policy_any ]
countryName = optional
stateOrProvinceName = optional
organizationName = optional
commonName = optional
emailAddress = optional

[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ server_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = host.docker.internal

[ crl_ext ]
authorityKeyIdentifier=keyid:always
EOF


echo "[+] Génération initiale des CRLs"
openssl ca -gencrl -config $ROOT_DIR/openssl-root.cnf -out $ROOT_DIR/crl/rootCA.crl
openssl ca -gencrl -config $INTER_DIR/openssl.cnf -out $INTER_DIR/crl/interCA.crl

cat $ROOT_DIR/crl/rootCA.crl $INTER_DIR/crl/interCA.crl > $INTER_DIR/crl/ca-chain.crl

echo "[✓] CA initialisée avec succès."

echo "[+] Génération du certif + clé pour frontend"
mkdir -p ../frontend/https
openssl genrsa -out ../frontend/https/frontend.key 4096

openssl req -new -key ../frontend/https/frontend.key -out ../frontend/https/frontend.csr \
  -subj "/C=BE/ST=Belgique/L=Namur/O=API https frontend/CN=frontend.localhost"

openssl ca -config $INTER_DIR/openssl.cnf -in ../frontend/https/frontend.csr -out ../frontend/https/frontend.pem -extensions server_cert -batch


echo "[+] Génération du certif + clé pour backend"
mkdir -p https
openssl genrsa -out https/backend.key 4096

openssl req -new -key https/backend.key -out https/backend.csr \
  -subj "/C=BE/ST=Belgique/L=Namur/O=API https backend/CN=backend.localhost"

openssl ca -config $INTER_DIR/openssl.cnf -in https/backend.csr -out https/backend.pem -extensions server_cert -batch

echo "[✓] Certificats générés pour frontend et backend."

echo "[+] Ajout Nécéssaire pour MTLS"
mkdir ../../MTLS/certs
cat ca/intermediate/certs/interCA.pem ca/root/certs/rootCA.pem > ../../MTLS/certs/ca-chain.pem

echo "[+] Générer clé + certif pour MTLS"
openssl genrsa -out ../../MTLS/certs/MTLS.key 2048

openssl req -new -key ../../MTLS/certs/MTLS.key -out ../../MTLS/certs/MTLS.csr \
  -subj "/C=BE/ST=Belgique/L=Namur/O=MTLS https/CN=MTLS.localhost"

openssl ca -config $INTER_DIR/openssl.cnf -in ../../MTLS/certs/MTLS.csr -out ../../MTLS/certs/MTLS.pem -extensions server_cert -batch

cat ../../MTLS/certs/MTLS.pem ca/intermediate/certs/interCA.pem > ../../MTLS/certs/server-fullchain.pem

cp ca/intermediate/certs/interCA.pem ../../MTLS/crl/interCA.pem
cp ca/intermediate/crl/ca-chain.crl ../../MTLS/crl/ca-chain.crl

docker build -t mtls-sot ../../MTLS

echo "[+] Génération du certif frontend LVCA"
mkdir -p ../../CLIENT_Frontend/https
openssl genrsa -out ../../CLIENT_Frontend/https/frontend.key 2048

openssl req -new -key ../../CLIENT_Frontend/https/frontend.key -out ../../CLIENT_Frontend/https/frontend.csr \
  -subj "/C=BE/ST=Belgique/L=Namur/O=API https frontend site/CN=frontendsite.localhost"

openssl ca -config $INTER_DIR/openssl.cnf -in ../../CLIENT_Frontend/https/frontend.csr -out ../../CLIENT_Frontend/https/frontend.pem -extensions server_cert -batch

echo "[+] Génération du certif backend Justin"
mkdir -p ../../BACKEND/https
openssl genrsa -out ../../BACKEND/https/backend.key 2048

openssl req -new -key ../../BACKEND/https/backend.key -out ../../BACKEND/https/backend.csr \
  -subj "/C=BE/ST=Belgique/L=Namur/O=API https backend site/CN=backendsite.localhost"

openssl ca -config $INTER_DIR/openssl.cnf -in ../../BACKEND/https/backend.csr -out ../../BACKEND/https/backend.pem -extensions server_cert -batch