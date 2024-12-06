#!/bin/bash

openssl req -x509 \
    -sha256 -days 356 \
    -nodes \
    -newkey rsa:2048 \
    -subj "/CN=rootCA/C=US/L=Manhattan" \
    -keyout rootCAKey.pem -out rootCACert.pem 

openssl genrsa -out serverBirdsKey.pem 2048
openssl genrsa -out serverComputersKey.pem 2048
openssl genrsa -out serverFoodKey.pem 2048
openssl genrsa -out serverCoolThingsKey.pem 2048
openssl genrsa -out serverFlipperHacksKey.pem 2048
openssl genrsa -out serverDirectoryServerKey.pem 2048


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

openssl req -new -key serverBirdsKey.pem -out serverBirds.csr -config csrBirds.conf
openssl req -new -key serverComputersKey.pem -out serverComputers.csr -config csrComputers.conf
openssl req -new -key serverFoodKey.pem -out serverFood.csr -config csrFood.conf
openssl req -new -key serverCoolThingsKey.pem -out serverCoolThings.csr -config csrCoolThings.conf
openssl req -new -key serverFlipperHacksKey.pem -out serverFlipperHacks.csr -config csrFlipperHacks.conf
openssl req -new -key serverDirectoryServerKey.pem -out serverDirectoryServer.csr -config csrDirectoryServer.conf

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
    -CA rootCACert.pem -CAkey rootCAKey.pem \
    -CAcreateserial -out serverBirdsCert.pem \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverComputers.csr \
    -CA rootCACert.pem -CAkey rootCAKey.pem \
    -CAcreateserial -out serverComputersCert.pem \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverFood.csr \
    -CA rootCACert.pem -CAkey rootCAKey.pem \
    -CAcreateserial -out serverFoodCert.pem \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverCoolThings.csr \
    -CA rootCACert.pem -CAkey rootCAKey.pem \
    -CAcreateserial -out serverCoolThingsCert.pem \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverFlipperHacks.csr \
    -CA rootCACert.pem -CAkey rootCAKey.pem \
    -CAcreateserial -out serverFlipperHacksCert.pem \
    -days 365 \
    -sha256 -extfile cert.conf

openssl x509 -req \
    -in serverDirectoryServer.csr \
    -CA rootCACert.pem -CAkey rootCAKey.pem \
    -CAcreateserial -out serverDirectoryServerCert.pem \
    -days 365 \
    -sha256 -extfile cert.conf

for file in *.crt; do
    mv -- "$file" "${file%.crt}.pem"
done

for file in *.key; do
    mv -- "$file" "${file%.key}.pem"
done
