#! /usr/bin/env bash

#Go to home directory
cd ~

#Install pelz dependencies
sudo apt install make cmake gcc openssl libssl-dev libffi-dev libcunit1 libcunit1-dev libcunit1-doc

#Install cJSON
git clone https://github.com/DaveGamble/cJSON.git
cd cJSON
mkdir build
cd build
cmake ..
make
sudo make install
cd ../..

#Install libkmip
git clone https://github.com/OpenKMIP/libkmip.git
cd libkmip
sudo make
sudo make install
cd ..

#Install uriparser
git clone https://github.com/uriparser/uriparser.git
cd uriparser
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DURIPARSER_BUILD_TESTS=OFF -DURIPARSER_BUILD_DOCS=OFF ..
make
sudo make install
cd ../..

#Setup Kmyth submodule and Install libs
cd pelz/kmyth
git submodule init
git submodule update
make libs
sudo make install libs
make clean
cd ..

#Make pelz
openssl genrsa -out sgx/pelz_enclave_private.pem -3 3072
make
