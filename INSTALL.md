# Installing and Building pelz

## Dependencies

### make, cmake, and gcc:

#### For Ubuntu 18:
	apt install make cmake gcc

#### For RHEL 8:
	dnf install -y make cmake gcc glibc

### Openssl:

#### For Ubuntu 18:
	apt install openssl libssl-dev libffi-dev

#### For RHEL 8:
	dnf install -y openssl openssl-devel libffi-devel

### Cunit:

#### For Ubuntu 18:
	apt install libcunit1 libcunit1-dev libcunit1-doc

#### For RHEL 8:
	dnf install -y CUnit

### cJSON:
cJSON is required to build pelz. See their [build instructions](https://github.com/DaveGamble/cJSON#building).

#### For RHEL 8:
	dnf install -y cjson-devel

### uriparser:
[uriparser](https://github.com/uriparser/uriparser) 0.9.0 or newer is required to build pelz. See their [build instructions](https://github.com/uriparser/uriparser#compilation).  
You may find it convenient to use the ```-DURIPARSER_BUILD_TESTS=OFF``` and ```-DURIPARSER_BUILD_DOCS=OFF``` flags.

#### For Ubuntu 18:
	apt install liburiparser-dev

### For RHEL 8:
	dnf install -y uriparser-devel

#### libkmip:
libkmip is required to build pelz. See their [installation instructions](https://libkmip.readthedocs.io/en/latest/installation.html).

### Intel SGX SDK and SGX SSL:
Pelz maintains its key table inside an SGX enclave. To support this functionality it requires the Intel Linux SGX SDK and Intel SGX SSL library. Instructions for installing these can be found here:
 * Install the [Intel Linux SGX SDK](https://github.com/intel/linux-sgx)
 * Install the [Intel SGX SSL library](https://github.com/intel/intel-sgx-ssl)

You must also create an enclave signing key, for example by running ```openssl genrsa -out sgx/pelz_enclave_private.pem -3 3072``` before building pelz.

The SGX SDK environment must be sourced before pelz can be run.

### kmyth submodule:
Pelz uses portions of the kmyth SGX enclave which it acquires by including kmyth as a git submodule and including the right files as part of its build process as described in the [kmyth SGX documentation](https://github.com/NationalSecurityAgency/kmyth/tree/main/sgx). Before attempting to build pelz you must initialize and update the kmyth submodule by:

    git submodule init
    git submodule update

#### kmyth logger:
The kmyth logger is used by pelz. It requires building the logger, but not all of kmyth. Follow below instuctions after initialize and update the kmyth submodule:

    cd kmyth
    make logger-lib
    make install

For more information, please see their [build instructions](https://github.com/NationalSecurityAgency/kmyth/blob/main/INSTALL.md).

#### kmyth utils:
The kmyth utils is used by pelz. It requires building the utils-lib, but not all of kmyth. Follow below instuctions after initialize and update the kmyth submodule:

    cd kmyth
    make utils-lib
    make install

For more information, please see their [build instructions](https://github.com/NationalSecurityAgency/kmyth/blob/main/INSTALL.md).
    
## Building pelz:
Once the dependencies are in place, building pelz is done by:

    make
    
 which places the executible in the ```bin/``` directory.
    
The unit test suite can be run via:

    make test
    
All build artifacts and binaries can be removed by running:

    make clean


## Pelz plugin for Accumulo:
Pelz comes with a plugin for Apache Accumulo. This allows the key encryption key(s) to be stored outside of Accumulo. Accumulo must be built after the plugin is installed. The script can be found in the accumulo_plugin directory. The script is used as follows:

    ./accumulo_plugin/setup_plugin.sh -i/-u -d /path/to/source/for/accumulo

For example, to install to a home directory containing the Accumulo source, you would execute:

    ./accumulo_plugin/setup_plugin.sh -i -d ~/accumulo

To uninstall:

    ./accumulo_plugin/setup_plugin.sh -u -d ~/accumulo

The choice to install/uninstall must always be specified, and a path to accumulo must always be provided.

### Testing with uno:
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
