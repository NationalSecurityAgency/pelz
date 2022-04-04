openssl ecparam -name secp384r1 -genkey -noout -out node_priv.pem
openssl req -new -x509 -key node_priv.pem -subj "/CN=TestClient" -out node_pub.pem -days 365

openssl ecparam -name secp384r1 -genkey -noout -out proxy_priv.pem
openssl req -new -x509 -key proxy_priv.pem -subj "/CN=localhost" -out proxy_pub.pem -days 365

