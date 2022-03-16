#!/bin/bash

# Install PyKMIP Dependancies
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install python-dev python-pip python3-dev python3-pip libffi-dev libssl-dev libsqlite3-dev

# Create PyKMIP directories
sudo mkdir /var/log/pykmip /etc/pykmip /etc/pykmip/certs /etc/pykmip/policies
sudo chown -R "${USER}" /var/log/pykmip /etc/pykmip

# Install PyKMIP
sudo pip3 install pykmip

# Generate certificates
cd /etc/pykmip/certs
curl -O https://raw.githubusercontent.com/arp102/PyKMIP/improvement/cert-san/bin/create_certificates.py
python3 create_certificates.py

mv client_certificate_john_doe.pem proxy_pub.pem
mv client_key_john_doe.pem proxy_priv.pem
mv server_certificate.pem pykmip_pub.pem
mv server_key.pem pykmip_priv.pem

# Create server config file
echo "
[server]
hostname=localhost
port=5696
ca_path=/etc/pykmip/certs/root_certificate.pem
key_path=/etc/pykmip/certs/pykmip_priv.pem
certificate_path=/etc/pykmip/certs/pykmip_pub.pem
auth_suite=TLS1.2
policy_path=/etc/pykmip/policies
enable_tls_client_auth=True
tls_cipher_suites=
    TLS_RSA_WITH_AES_128_CBC_SHA256
    TLS_RSA_WITH_AES_256_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    ECDHE-ECDSA-AES256-GCM-SHA384
    ECDHE-RSA-AES256-GCM-SHA384
    ECDHE-ECDSA-AES256-SHA384
    ECDHE-RSA-AES256-SHA384
logging_level=DEBUG
database_path=/etc/pykmip/pykmip.db
" > /etc/pykmip/server.conf

# Create client config file
echo "
[client]
host=localhost
port=5696
keyfile=/etc/pykmip/certs/proxy_priv.pem
certfile=/etc/pykmip/certs/proxy_pub.pem
cert_reqs=CERT_REQUIRED
ssl_version=PROTOCOL_SSLv23
ca_certs=/etc/pykmip/certs/root_certificate.pem
do_handshake_on_connect=True
suppress_ragged_eofs=True
username=example_username
password=example_password
" > /etc/pykmip/pykmip.conf
