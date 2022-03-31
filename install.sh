#! /usr/bin/env bash

# This script is provided as an example for building the prerequisites for pelz. It is not intended
# to be maintained. In some cases it may help simplify installation of dependencies.
#
# This script has been tested on Ubuntu and successfully built pelz and its dependencies. It does
# not build the required Intel SGX and TPM 2.0 SDKs or simulators. The build process for the 
# software required to run Intel SGX and TPM 2.0 simulators changes more frequently than the other
# tools built in this script, so we do not provide them. Instead, locations for install info for
# those can be found in pelz's INSTALL.md. This script will fail if these SDKs are not installed.
#
# This script will download and compile the source code for other projects. Please consult their
# licenses prior to use or redistribution of binaries, source code, or derivative works.

# This script defaults to downloading the various projects within the user's home directory. This 
# can be modified to any desired destination, and all downloads will occur relative to that 
# directory. Because posession of this script implies pelz has already been downloaded, this is 
# assumed to be the directory containing pelz
SOURCE_ROOT=~
pushd $SOURCE_ROOT

# As of 03/14/2022, these dependencies were required for Ubuntu to build pelz. Some of the projects
# built later might be eventually be packaged by Ubuntu.
sudo apt install make cmake gcc openssl libssl-dev libffi-dev libcunit1 libcunit1-dev libcunit1-doc

# Downloads, builds, and installs the cJSON library
git clone https://github.com/DaveGamble/cJSON.git
pushd cJSON
mkdir build
pushd build
cmake ..
make
sudo make install
popd
popd

# Downloads, builds, and installs the libkmip library
git clone https://github.com/OpenKMIP/libkmip.git
pushd libkmip
sudo make
sudo make install
popd

# Downloads, builds, and installs the uriparser library
git clone https://github.com/uriparser/uriparser.git
pushd uriparser
mkdir build
pushd build
cmake -DCMAKE_BUILD_TYPE=Release -DURIPARSER_BUILD_TESTS=OFF -DURIPARSER_BUILD_DOCS=OFF ..
make
sudo make install
popd
popd

# Downloads, builds, and installs the Kmyth library. Kmyth makes using the TPM and SGX enclaves
# easier, and it is built as a submodule for pelz.
pushd pelz
git submodule init
git submodule update
pushd kmyth
make 
sudo make install
make clean
popd

# A key is required to build the pelz enclave. This .pem will be used to sign the enclave.
openssl genrsa -out sgx/pelz_enclave_private.pem -3 3072
make
popd
