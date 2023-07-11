#!/bin/bash

# Use a unique identifier in the subject field to avoid name conflicts in the pelz ca table.
random_id=$(tr -dc A-Za-z0-9 </dev/urandom | head -c8)

# Generate CA key+cert
openssl ecparam -name secp521r1 -genkey -noout -out ca_priv.pem
openssl req -new -x509 -key ca_priv.pem -subj "/C=US/O=pelz/CN=TestCA-${random_id}" -out ca_pub.pem -days 365
openssl x509 -in ca_pub.pem -inform pem -out ca_pub.der -outform der

# Generate key+csr+cert for demo client, signed by the CA
openssl ecparam -name secp384r1 -genkey -noout -out worker_priv.pem
openssl pkey -in worker_priv.pem -inform pem -out worker_priv.der -outform der

openssl req -new -sha512 -key worker_priv.pem -subj "/CN=TestWorker-${random_id}" -out worker_pub.csr
openssl x509 -req -sha256 -in worker_pub.csr -out worker_pub.pem -CAcreateserial -CAkey ca_priv.pem -CA ca_pub.pem -days 365
openssl x509 -req -sha256 -in worker_pub.csr  -outform der -out worker_pub.der -CAcreateserial -CAkey ca_priv.pem -CA ca_pub.pem -days 365
