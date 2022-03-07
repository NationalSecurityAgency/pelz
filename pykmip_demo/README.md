# PyKMIP Usage Demo

## Introduction
Starting, with Accumulo, sending pelz a FEK to be encrypted by a KEK from a MyKMIP key server.  Pelz gets the FEK and the UID for the KEK.
SGX and TPM assumed to already be installed and working.

## Steps for End to End demo of MyKMIP, Accumulo, and pelz. 

### Pelz Installation Steps
1.  Open terminal
2.	Clone pelz repo and run install script

		git clone https://github.com/NationalSecurityAgency/pelz.git
		cd pelz
		./install.sh

### Accumulo and Accumulo Plugin Installation Steps 
3. Download the Accumulo source and setup pelz plugin

		cd ..
		git clone https://github.com/apache/accumulo.git
		cd pelz/pykmip_demo/accumulo_plugin
		./setup_plugin.sh -i -d ~/accumulo/
		cd ..

### PyKMIP Server Installaiton/Setep Steps
4.  Run PyKMIP Script in a separate terminal

		./PyKMIP_setup.sh

5.  Run the server in a separate terminal

		pykmip-server

6.  Register keys with the server

		./register_keys_pykmip.sh


### Certificate and PKey Creation/Installation Steps
7.	Generate Certificates and PKeys for server and client then seal

		cd ../test/data
		./gen_test_keys_certs.bash
		openssl x509 -in server_cert_test.pem -inform pem -out server_cert_test.der -outform der
		openssl pkey -in client_priv_test.pem -inform pem -out client_priv_test.der -outform der
		cd ../..
		./bin/pelz seal test/data/server_cert_test.der -o test/data/server_cert_test.der.nkl
		./bin/pelz seal test/data/client_priv_test.der -o test/data/client_priv_test.der.nkl

8.	Run the pelz-service in a separate terminal

		./bin/pelz-service -m 200

9.	Load server certificate and client PKey

		./bin/pelz pki load cert test/data/server_cert_test.der.nkl
		./bin/pelz pki load private test/data/client_priv_test.der.nkl

### Proxy Server Setep Steps
10.	Build the proxy server in a separate terminal

		cd pelz/kmyth/sgx
		make clean demo-all
		cd ../..
		./kmyth/sgx/demo/bin/tls-proxy -r test/data/server_priv_test.pem -u test/data/client_cert_test.pem -p 7000 -I localhost -P 5696 -C /etc/pykmip/certs/root_certificate.pem -R /etc/pykmip/certs/client_key_john_doe.pem -U /etc/pykmip/certs/client_certificate_john_doe.pem

### End to End Demo Step
11. Run Accumulo Test

		cd ../accumulo
		mvn clean
		mvn test

