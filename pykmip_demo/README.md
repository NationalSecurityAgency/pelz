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

### Certificate and PKey Creation/Installation Steps
1.  Start in pelz directory after Proxy Server Setup

		cd test/data
		./gen_test_keys_certs.bash
		openssl x509 -in server_cert_test.pem -inform pem -out server_cert_test.der -outform der
		openssl pkey -in client_priv_test.pem -inform pem -out client_priv_test.der -outform der
		cd ../..
		./bin/pelz-service

2.	In a separate terminal

		./bin/pelz seal test/data/server_cert_test.der -o test/data/server_cert_test.der.nkl
		./bin/pelz seal test/data/client_priv_test.der -o test/data/client_priv_test.der.nkl
		./bin/pelz pki load cert test/data/server_cert_test.der.nkl
		./bin/pelz pki load private test/data/client_priv_test.der.nkl


### PyKMIP Server Installaiton/Setep Steps
1.  Run PyKMIP Script (sudo based on your permissions) in a separate terminal

		./PyKMIP_setup.sh

2.	Run the server in a separate terminal (sudo based on your permissions)

		pykmip-server

3.	Register keys with the server

		./register_keys_pykmip.sh

### Proxy Server Setep Steps
1. Build the kmyth programs in a separate terminal

		cd kmyth/sgx
		make clean demo-all
		cd ../..
		./kmyth/sgx/demo/bin/tls-proxy -r test/data/server_priv_test.pem -u test/data/client_cert_test.pem -p 7000 -I localhost -P 5696 -C /etc/pykmip/certs/root_certificate.pem -R /etc/pykmip/certs/client_key_john_doe.pem -U /etc/pykmip/certs/client_certificate_john_doe.pem

### End to End Demo Step
1. Start test by running Accumulo

