# Generate key+cert for local ECDH application
openssl ecparam -name secp384r1 -genkey -noout -out node_priv.pem
openssl req -new -x509 -key node_priv.pem -subj "/CN=TestClient" -out node_pub.pem -days 365

# Generate key+cert for remote ECDH service
openssl ecparam -name secp384r1 -genkey -noout -out proxy_priv.pem
openssl req -new -x509 -key proxy_priv.pem -subj "/CN=localhost" -out proxy_pub.pem -days 365

# Generate CA key+cert
openssl req -new -x509 -nodes -subj "/CN=PelzTest-CA" -keyout ca_priv.pem -out ca_pub.pem -days 365

# Generate key+csr+cert for remote client, signed by the CA
openssl ecparam -name secp384r1 -genkey -noout -out worker_priv.pem
openssl req -new -sha512 -key worker_priv.pem -subj "/CN=TestWorker" -out worker_pub.csr
openssl x509 -req -sha256 -in worker_pub.csr -out worker_pub.pem -CAcreateserial -CAkey ca_priv.pem -CA ca_pub.pem -days 365

#Convert X509 keys and certs to DER format
openssl x509 -in node_pub.pem -inform pem -out node_pub.der -outform der
openssl x509 -in proxy_pub.pem -inform pem -out proxy_pub.der -outform der
openssl pkey -in node_priv.pem -inform pem -out node_priv.der -outform der
openssl x509 -in ca_pub.pem -inform pem -out ca_pub.der -outform der
