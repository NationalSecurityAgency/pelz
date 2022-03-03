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
1.  Start in pelz directory

		cd test/data/
    ./gen_test_keys_certs.bash
    cd ../..
    openssl x509 -in test/data/server_cert_test.pem -inform pem -out test/data/server_cert_test.der -outform der
    openssl pkey -in test/data/client_priv_test.pem -inform pem -out test/data/client_priv_test.der -outform der
    ./bin/pelz seal test/data/server_cert_test.der -o test/data/server_cert_test.der.nkl
    ./bin/pelz seal test/data/client_priv_test.der -o test/data/client_priv_test.der.nkl
    ./bin/pelz pki load cert test/data/server_cert_test.der.nkl
    ./bin/pelz pki load private test/data/client_priv_test.der.nkl

### PyKMIP Server Installaiton/Setep Steps

### Proxy Server Installaiton/Setep Steps

### End to End Demo Step
1. Start test by running Accumulo

