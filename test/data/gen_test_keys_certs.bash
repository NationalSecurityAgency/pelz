# Generate CA key+cert
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out ca_priv.pem

openssl req -new \
            -x509 \
            -config ca.cnf \
            -key ca_priv.pem \
            -days 365 \
            -out ca_pub.pem

openssl x509 -in ca_pub.pem \
             -inform pem \
             -out ca_pub.der \
             -outform der

# Generate key+cert for local pelz service node
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out node_priv.pem

openssl pkey -in node_priv.pem \
             -inform pem \
             -outform der \
             -out node_priv.der

openssl req -new \
            -config node.cnf \
            -key node_priv.pem \
            -out node.csr

openssl x509 -req \
             -in node.csr \
             -extfile node.cnf \
             -extensions v3_ext \
             -CA ca_pub.pem \
             -CAkey ca_priv.pem \
             -CAcreateserial \
             -days 365 \
             -out node_pub.pem

openssl x509 -inform pem \
             -in node_pub.pem \
             -outform der \
             -out node_pub.der

# Generate key+cert for test ECDH proxy used by pelz node to access key server
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out proxy_priv.pem

openssl req -new \
            -config proxy.cnf \
            -key proxy_priv.pem \
            -out proxy.csr

openssl x509 -req \
             -in proxy.csr \
             -extfile proxy.cnf \
             -extensions v3_ext \
             -CA ca_pub.pem \
             -CAkey ca_priv.pem \
             -CAcreateserial \
             -days 365 \
             -out proxy_pub.pem

openssl x509 -inform pem \
             -in proxy_pub.pem \
             -outform der \
             -out proxy_pub.der

# Generate key+cert for test KMIP (simplified) key server
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out server_priv.pem

openssl req -new \
            -config server.cnf \
            -key server_priv.pem \
            -out server.csr

openssl x509 -req \
             -in server.csr \
             -extfile server.cnf \
             -extensions v3_ext \
             -CA ca_pub.pem \
             -CAkey ca_priv.pem \
             -CAcreateserial \
             -days 365 \
             -out server_pub.pem

openssl x509 -inform pem \
             -in server_pub.pem \
             -outform der \
             -out server_pub.der

# Generate key+cert for test worker enclave (pelz client)
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out worker_priv.pem

openssl req -new \
            -config worker.cnf \
            -key worker_priv.pem \
            -out worker.csr

openssl x509 -req \
             -in worker.csr \
             -extfile worker.cnf \
             -extensions v3_ext \
             -CA ca_pub.pem \
             -CAkey ca_priv.pem \
             -CAcreateserial \
             -days 365 \
             -out worker_pub.pem \
