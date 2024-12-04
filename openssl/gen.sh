#!/bin/bash

openssl req -x509 \
    -sha256 -days 356 \
    -nodes \
    -newkey rsa:2048 \
    -subj "/CN=rootCA/C=US/L=Manhattan" \
    -keyout rootCA.key -out rootCA.crt 

openssl genrsa -out server.key 2048

cat > csrBirds.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = Kansas
L = Manhattan
O = KSU
OU = cis525
CN = Birds

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 192.168.1.5
IP.2 = 192.168.1.6
EOF

cat > csrComputers.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = Kansas
L = Manhattan
O = KSU
OU = cis525
CN = Computers

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 192.168.1.5
IP.2 = 192.168.1.6
EOF

cat > csrFood.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = Kansas
L = Manhattan
O = KSU
OU = cis525
CN = Food

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 192.168.1.5
IP.2 = 192.168.1.6
EOF

cat > csrCoolThings.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = Kansas
L = Manhattan
O = KSU
OU = cis525
CN = Cool Things

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 192.168.1.5
IP.2 = 192.168.1.6
EOF

cat > csrFlipperHacks.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = Kansas
L = Manhattan
O = KSU
OU = cis525
CN = Flipper Hacks

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 192.168.1.5
IP.2 = 192.168.1.6
EOF

cat > csrDirectoryServer.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = Kansas
L = Manhattan
O = KSU
OU = cis525
CN = Directory Server

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 192.168.1.5
IP.2 = 192.168.1.6
EOF

openssl req -new -key server.key -out serverBirds.csr -config csrBirds.conf
openssl req -new -key server.key -out serverComputers.csr -config csrComputers.conf
openssl req -new -key server.key -out serverFood.csr -config csrFood.conf
openssl req -new -key server.key -out serverCoolThings.csr -config csrCoolThings.conf
openssl req -new -key server.key -out serverFlipperHacks.csr -config csrFlipperHacks.conf
openssl req -new -key server.key -out serverDirectoryServer.csr -config csrDirectoryServer.conf

cat > cert.conf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = demo.mlopshub.com
EOF

openssl x509 -req \
    -in serverBirds.csr \
    -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out serverBirds.crt \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverComputers.csr \
    -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out serverComputers.crt \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverFood.csr \
    -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out serverFood.crt \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverCoolThings.csr \
    -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out serverCoolThings.crt \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverFlipperHacks.csr \
    -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out serverFlipperHacks.crt \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverDirectoryServer.csr \
    -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out serverDirectoryServer.crt \
    -days 365 \
    -sha256 -extfile cert.conf
