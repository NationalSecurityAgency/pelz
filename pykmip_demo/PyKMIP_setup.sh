#!/bin/bash
SOURCE_ROOT=~
pushd $SOURCE_ROOT

# Install PyKMIP Dependencies
sudo apt-get install python3 libffi-dev libssl-dev libsqlite3-dev

# Create PyKMIP directories
if [ ! -d /var/log/pykmip ]; then
  sudo mkdir /var/log/pykmip 
  sudo chown -R "${USER}" /var/log/pykmip
fi
if [ ! -d /etc/pykmip ]; then
  sudo mkdir /etc/pykmip 
  sudo chown -R "${USER}" /etc/pykmip
fi
if [ ! -d /etc/pykmip/certs ]; then
  sudo mkdir /etc/pykmip/certs 
fi
if [ ! -d /etc/pykmip/policies ]; then
  sudo mkdir /etc/pykmip/policies
fi

# Install PyKMIP
if [ ! -d PyKMIP ]; then
  git clone https://github.com/OpenKMIP/PyKMIP.git
fi
test -f /usr/local/bin/pykmip-server
if [ $? -ne 0 ]; then
  pushd PyKMIP
  sudo python3 setup.py install
fi

# Generate certificates
test -f /etc/pykmip/certs/root_key.pem
if [ $? -ne 0 ]; then 
  pushd /etc/pykmip/certs
  python3 $SOURCE_ROOT/PyKMIP/bin/create_certificates.py
fi

# Certificate names come from the create_certificates.py script
test -f /etc/pykmip/certs/pykmip_priv.pem
if [ $? -ne 0 ]; then 
  pushd /etc/pykmip/certs
  mv client_certificate_john_doe.pem proxy_pub.pem
  mv client_key_john_doe.pem proxy_priv.pem
  mv server_certificate.pem pykmip_pub.pem
  mv server_key.pem pykmip_priv.pem
fi

# Create server config file
test -f /etc/pykmip/server.conf
if [ $? -ne 0 ]; then 
  echo "
[server]
hostname=localhost
port=5690
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
fi

# Create client config file
test -f /etc/pykmip/pykmip.conf
if [ $? -ne 0 ]; then
  echo "
[client]
host=localhost
port=5690
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
fi
