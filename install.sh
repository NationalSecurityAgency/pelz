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
if [ ! -d cJSON ]; then
  git clone https://github.com/DaveGamble/cJSON.git
fi
pushd cJSON
test -f /usr/local/lib/libcjson.so
if [ $? -ne 0 ]; then
  # build and install freshly cloned code base
  echo "cJSON: not installed ... build and install"
  mkdir -p build
  pushd build
  cmake ..
  make
  sudo make install
  sudo ldconfig
  popd
fi
git remote update && git fetch
if [ $(git rev-parse HEAD) != $(git rev-parse @{u}) ]; then
  # newer code available, get update decision from user
  update_flag=0
  while true; do
    read -p "cJSON: newer code available ... update? (yes/no)" REPLY
    case $REPLY in
      yes | Yes | YES )
        update_flag=1
        break;;
      no | No | NO )
        break;;
    esac
  done
  if [ $update_flag ]; then
    # update repo, uninstall, rebuild, reinstall
    git pull
    sudo make uninstall
    make clean
    make
    sudo make install
    sudo ldconfig
  fi
else
  echo "cJSON: code at latest revision"
fi
popd

# Downloads, builds, and installs the libkmip library
# libkmip Software Library
if [ ! -d libkmip ]; then
  git clone https://github.com/OpenKMIP/libkmip.git
fi
pushd libkmip
test -f /usr/local/lib/libkmip.so
if [ $? -ne 0 ]; then
  # build and install freshly cloned code base
  echo "libkmip: not installed ... build and install"
  make
  sudo make install
  sudo ldconfig
fi
git remote update && git fetch
if [ $(git rev-parse HEAD) != $(git rev-parse @{u}) ]; then
  # newer code available, get update decision from user
  update_flag=0
  while true; do
    read -p "libkmip: newer code available ... update? (yes/no)" REPLY
    case $REPLY in
      yes | Yes | YES )
        update_flag=1
        break;;
      no | No | NO )
        break;;
    esac
  done
  if [ $update_flag ]; then
    # update repo, uninstall, rebuild, reinstall
    git pull
    sudo make uninstall
    make clean
    make
    sudo make install
    sudo ldconfig
  fi
else
  echo "libkmip: code at latest revision"
fi
popd

# Downloads, builds, and installs the uriparser library
if [ ! -d uriparser ]; then
  git clone https://github.com/uriparser/uriparser.git
fi
pushd uriparser
test -f /usr/local/lib/liburiparser.so
if [ $? -ne 0 ]; then
  # build and install freshly cloned code base
  echo "uriparser: not installed ... build and install"
  mkdir -p build
  pushd build
  cmake -DCMAKE_BUILD_TYPE=Release ..
  make
  sudo make install
  sudo ldconfig
  popd
fi
git remote update && git fetch
if [ $(git rev-parse HEAD) != $(git rev-parse @{u}) ]; then
  # newer code available, get update decision from user
  update_flag=0
  while true; do
    read -p "uriparser: newer code available ... update? (yes/no)" REPLY
    case $REPLY in
      yes | Yes | YES )
        update_flag=1
        break;;
      no | No | NO )
        break;;
    esac
  done
  if [ $update_flag ]; then
    # update repo, uninstall, rebuild, reinstall
    git pull
    sudo make uninstall
    make clean
    make
    sudo make install
    sudo ldconfig
  fi
else
  echo "uriparser: code at latest revision"
fi
popd

# Downloads, builds, and installs the Kmyth library. Kmyth makes using the TPM and SGX enclaves
# easier, and it is built as a submodule for pelz.
pushd pelz
git submodule init
git submodule update
test -f /usr/local/lib/libkmyth-tpm.so
if [ $? -ne 0 ]; then
  pushd kmyth
  make 
  sudo make install
  make clean
  popd
fi

# A key is required to build the pelz enclave. This .pem will be used to sign the enclave.
test -f sgx/pelz_enclave_private.pem
if [ $? -ne 0 ]; then
  openssl genrsa -out sgx/pelz_enclave_private.pem -3 3072
fi
test -f bin/pelz
if [ $? -ne 0 ]; then
  make
  popd
fi
