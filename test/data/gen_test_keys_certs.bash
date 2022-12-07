# Generate CA key+cert
openssl ecparam -name secp521r1 -genkey -noout -out ca_priv.pem
openssl req -new -x509 -key ca_priv.pem -subj "/C=US/O=pelz/CN=TestCA" -out ca_pub.pem -days 365
openssl x509 -in ca_pub.pem -inform pem -out ca_pub.der -outform der

# Generate key+cert for local ECDH application
openssl ecparam -name secp384r1 -genkey -noout -out node_priv.pem
openssl pkey -in node_priv.pem -inform pem -out node_priv.der -outform der
openssl req -new -sha512 -key node_priv.pem -subj "/C=US/O=pelz/CN=TestClient" -out node_cert.csr
openssl x509 -req -in node_cert.csr -CA ca_pub.pem -CAkey ca_priv.pem -CAcreateserial -out node_pub.pem -days 365 -sha256
openssl x509 -req -in node_cert.csr -CA ca_pub.pem -CAkey ca_priv.pem -CAcreateserial -out node_pub.der -outform der -days 365 -sha256

# Generate key+cert for proxy ECDH service
openssl ecparam -name secp384r1 -genkey -noout -out proxy_priv.pem
openssl req -new -sha512 -key proxy_priv.pem -subj "/C=US/O=pelz/CN=localhost" -out proxy_cert.csr
openssl x509 -req -in proxy_cert.csr -CA ca_pub.pem -CAkey ca_priv.pem -CAcreateserial -out proxy_pub.pem -days 365 -sha256
openssl x509 -req -in proxy_cert.csr -CA ca_pub.pem -CAkey ca_priv.pem -CAcreateserial -out proxy_pub.der -outform der -days 365 -sha256

# Generate key+cert for server ECDH service
openssl ecparam -name secp521r1 -genkey -noout -out server_priv.pem
openssl req -new -sha256 -key server_priv.pem -subj "/C=US/O=pelz/CN=127.0.0.1" -out server_cert.csr
openssl x509 -req -in server_cert.csr -CA ca_pub.pem -CAkey ca_priv.pem -CAcreateserial -out server_pub.pem -days 365 -sha256

# Generate key+csr+cert for remote client, signed by the CA
openssl ecparam -name secp384r1 -genkey -noout -out worker_priv.pem
openssl req -new -sha512 -key worker_priv.pem -subj "/CN=TestWorker" -out worker_pub.csr
openssl x509 -req -sha256 -in worker_pub.csr -out worker_pub.pem -CAcreateserial -CAkey ca_priv.pem -CA ca_pub.pem -days 365

