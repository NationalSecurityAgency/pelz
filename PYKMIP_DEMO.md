# MyKMIP Usage Demo

## Introduction
Starting, with Accumulo, sending pelz a FEK to be encrypted by a KEK from a MyKMIP key server.  Pelz gets the FEK and the UID for the KEK.

## Steps for End to End demo of MyKMIP, Accumulo, and pelz. 

### Pelz Installation Steps
Installation of pelz (follow the installing and building pelz instruction to have pelz installed as a service from the INSTALL.md).
 * Ensure pelz is set to handle the expected socket connections. (Pelz default is 100 and Accumulo test does more then that)
 * Load the needed certs and pkeys. (See create and load cert steps)

### Accumulo and Accumulo Plugin Installation Steps 
1. Download the Accumulo source code.
2. Follow the Pelz plugin for Accumulo instructions in the INSTALL.md.

### PyKMIP Server Installaiton/Setep Steps
1.  Run PyKMIP Script (sudo based on your permissions)

		./PyKMIP_setup.sh

2.	Run the server in a separate terminal (sudo based on your permissions)

		pykmip-server

3.	Register keys with the server

		./register_keys_pykmip.sh

### Proxy Server Setep Steps
1. Build the kmyth programs in a separate terminal

		cd kmyth/sgx
		make clean demo-all demo-test-keys-certs
		./demo/bin/tls-proxy -r demo/data/server_priv_test.pem -u demo/data/client_cert_test.pem -p 7000 -I localhost -P 5696 -C /etc/pykmip/certs/root_certificate.pem -R /etc/pykmip/certs/client_key_john_doe.pem -U /etc/pykmip/certs/client_certificate_john_doe.pem

### Certificate and PKey Creation/Installation Steps
1.  Start in pelz directory after Proxy Server Setup

		openssl x509 -in kmyth/sgx/demo/data/server_cert_test.pem -inform pem -out server_cert_test.der -outform der
		openssl pkey -in kmyth/sgx/demo/data/client_priv_test.pem -inform pem -out client_priv_test.der -outform der
		./bin/pelz seal server_cert_test.der -o server_cert_test.der.nkl
		./bin/pelz seal client_priv_test.der -o client_priv_test.der.nkl
		./bin/pelz pki load cert server_cert_test.der.nkl
		./bin/pelz pki load private client_priv_test.der.nkl

### End to End Demo Step
1. Start test by running Accumulo

