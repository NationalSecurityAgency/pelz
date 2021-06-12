# Installing and Building pelz

## Dependencies

### For Ubuntu:
apt install make cmake indent gcc openssl libssl-dev libffi-dev libcunit1 libcunit1-dev libcunit1-doc

#### cJSON:
cJSON is required to build pelz.  

    git clone https://github.com/DaveGamble/cJSON.git
    cd cJSON
    mkdir build
    cd build
    cmake ..
    make
    make install

For more information on building cJSON, please see their [build instructions](https://github.com/DaveGamble/cJSON#building).

#### uriparser
[uriparser](https://github.com/uriparser/uriparser) 0.9.0 or newer is required to build pelz. See their [build instructions](https://github.com/uriparser/uriparser/README#compilation). 

#### kmyth logger:
The kmyth logger is used by pelz. It requires building the logger, but not all of kmyth.  

    git clone https://github.com/NationalSecurityAgency/kmyth.git
    cd kmyth/tpm2
    make logger-lib
    make install

For more information, please see their [build instructions](https://github.com/NationalSecurityAgency/kmyth/blob/main/tpm2/INSTALL.md).
## Building pelz
Once the dependencies are in place, building pelz is done by:

    make
    make install

#### Building pelz-sgx
Pelz can now be built to keep its key table inside an SGX enclave. This functionality is currently extremely experimental, and installation is not supported. To test the pelz-sgx functionality:
 * Install the [Intel Linux SGX SDK](https://github.com/intel/linux-sgx)
 * Install the [Intel SGX SSL library](https://github.com/intel/intel-sgx-ssl)
 * Generate or install the enclave signing key. For example, use ```openssl genrsa -out sgx/pelz_enclave_private.pem -3 3072```
 * Source the SGX SDK environment

With all the setup complete, pelz-sgx can be built by:

     make -f sgx.mk

and executed by running

	./bin/pelz-sgx

All pelz-sgx related files can be cleaned up with

    make -f sgx.mk clean

## Pelz as a service
The service_setup.sh script can be used to initialize pelz as a Linux service. It must be run with root privileges.

To install:

	sh service-setup.sh -i

To uninstall:

	sh service-setup.sh -u

## Pelz plugin for Accumulo
Pelz comes with a plugin for Apache Accumulo. This allows the key encryption key(s) to be stored outside of Accumulo. Accumulo must be built after the plugin is installed. The script can be found in the accumulo_plugin directory. The script is used as follows:

    ./accumulo_plugin/setup_plugin.sh -i/-u -d /path/to/source/for/accumulo

For example, to install to a home directory containing the Accumulo source, you would execute:

    ./accumulo_plugin/setup_plugin.sh -i -d ~/accumulo

To uninstall:

    ./accumulo_plugin/setup_plugin.sh -u -d ~/accumulo

The choice to install/uninstall must always be specified, and a path to accumulo must always be provided.

### Testing with uno
Uno provides an easy way to build a local instance of Accumulo for testing. Instructions for installing can be found [here](https://github.com/apache/fluo-uno). Once downloaded and configured, but prior to running "./bin/uno fetch accumulo" the following must occur:  

1. Download the [Accumulo source code](https://github.com/apache/accumulo).
2. The Accumulo plugin must be installed. See [above](Pelz plugin for Accumulo) for instructions.
3. From the fluo-uno directory:  
    a. cp conf/uno.conf conf/uno-local.conf  
    b. Open uno-local.conf in your favorite text editor  
    c. Uncomment and change the ACCUMULO_REPO configuration (line 46). This is the same location the plugin was installed.  
    d. Add "accumulo-encryption" to the POST_INSTALL_PLUGINS (line 151)  
    e. Save your changes and open plugins/accumulo-encryption.sh in a text editor  
    f. Change:  
        instance.crypto.service=org.apache.accumulo.core.cryptoImpl.AESCryptoService to  
        instance.crypto.service=org.apache.accumulo.core.cryptoImpl.PelzCryptoService  
    g. Save your changes  
4. Continue following uno instructions (fetch, setup, etc)

For testing, see the [Apache Accumulo Testing Suite](https://github.com/apache/accumulo-testing).
