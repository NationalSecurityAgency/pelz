# Attestation Demo

This directory contains a custom pelz client demonstrating a new method of connecting to pelz.
The new client is primarily based on the LocalAttestation sample code from the linux-sgx repo
(https://github.com/intel/linux-sgx/tree/master/SampleCode/LocalAttestation),
and much of its code is taken directly from that example with minimal changes.

The client establishes an encrypted communication channel to pelz using an ECDH protocol defined in libsgx.
During the key exchange, both parties are able to verify that they are running on the same SGX hardware instance,
and they can also authenticate using additional metadata such as the MRSIGNER value.


## Quick Start

First, build and run the pelz-service application.
Then, use these commands to build and run the demo client:

``` bash
cd attestation_demo
openssl genrsa -out EnclaveInitiator/EnclaveInitiator_private_test.pem -3 3072
make
python3 run_demo.py
```

The run_demo.py script first uses the demo client to simulate application data at rest
by encrypting a data file, wrapping the "data encryption key" using pelz,
then storing the encrypted data and wrapped key together in a new file.
Then it uses the demo client to unwrap the data encryption key using pelz,
then decrypt the data and count the number of occurrences of a specific search term.
(The decrypted data does not leave the protected SGX enclave.)


## Building the Client Application

Before building, install the Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux* OS.
(This is also required to build pelz.)

You must also generate an enclave signing key before building
(e.g. by running `openssl genrsa -out EnclaveInitiator/EnclaveInitiator_private_test.pem -3 3072`),
otherwise you will be prompted to create one during the build.

This demo client has the same SGX build options as pelz
and the same default values (SGX_MODE=SIM SGX_DEBUG=1).
The most common build settings are listed below.

```
a. Hardware Mode, Debug build:
$ make SGX_MODE=HW
b. Hardware Mode, Pre-release build:
$ make SGX_MODE=HW SGX_PRERELEASE=1 SGX_DEBUG=0
c. Hardware Mode, release build:
$ make SGX_MODE=HW SGX_DEBUG=0
d. Simulation Mode, Debug build:
$ make SGX_MODE=SIM
e. Simulation Mode, Pre-release build:
$ make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
f. Simulation Mode, Release build:
$ make SGX_MODE=SIM SGX_DEBUG=0
g. Use Local Attestation 2.0 protocol, Hardware Mode, Debug build:
$ make SGX_MODE=HW LAv2=1
    Note: Local Attestation 2.0 protocol will be used if 'LAv2' is defined.
```

When the build is successful, the executable binary will be found in the `bin` directory.


## Running the Client Application

Before running, install the SGX driver and PSW for Linux* OS.
(This is also required to run pelz.)

The client has three operating modes:
* encrypt: Encrypt a file, wrap the data encryption key using pelz,
  then store the encrypted data and wrapped key together in a new file.
* decrypt: Open a file produced by the `encrypt` operation,
  unwrap the data encryption key using pelz,
  then decrypt the data and store the plaintext in a new file.
* search: Open a file produced by the `encrypt` operation,
  unwrap the data encryption key using pelz,
  then decrypt the data and count the number of occurrences of a specific search term.

Usage Details:
```
Usage: ./bin/demo_worker COMMAND OPTIONS ...

Commands:
  encrypt KEK_ID
  decrypt
  search KEYWORD

Options:
-i DATA_FILE, --input-file=DATA_FILE   (required for all commands)
-o OUT_FILE,  --output-file=OUT_FILE   (required for encrypt and decrypt commands)
-r PRIV_KEY,  --signing-key=PRIV_KEY   (required for all commands, DER format)
-u PUB_KEY,   --signing-cert=PUB_KEY   (required for all commands, DER X509 format)
-h, --help

Note: This demo program is not designed to handle large input files (>500 KB).
```

Note: The client will not work properly if run outside of the "attestation_demo" directory.
E.g. the command `attestation_demo/bin/demo_worker` will not work properly.
This is consistent with the behavior of the pelz and pelz-service binaries.
