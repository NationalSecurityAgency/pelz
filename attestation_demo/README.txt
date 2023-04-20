Attestation Demo
================

This directory contains a custom Pelz client demonstrating a new method of connecting to the Pelz server.
The new client is primarily based on the LocalAttestation sample code from the linux-sgx repo
(https://github.com/intel/linux-sgx/tree/master/SampleCode/LocalAttestation),
and much of its code is taken directly from that example with minimal changes.

The client and server establish an encrypted communication channel using an ECDH protocol defined in libsgx.
During the key exchange, both parties are able to verify that they are running on the same SGX hardware instance,
and they can also authenticate using additional metadata such as the MRSIGNER value.


Quick Start
-----------

Use these commands to run the demo client:

    cd attestation_demo
    openssl genrsa -out EnclaveInitiator/EnclaveInitiator_private_test.pem -3 3072
    make
    ./bin/appinitiator


Building the Demo Client
------------------------

Before building, install the Intel(R) Software Guard Extensions (Intel(R) SGX) SDK for Linux* OS.
(This is also required to build the Pelz server.)

You must also generate an enclave signing key before building
(e.g. by running `openssl genrsa -out EnclaveInitiator/EnclaveInitiator_private_test.pem -3 3072`),
otherwise you will be prompted to create one during the build.

This demo client has the same SGX build options as the Pelz server
and the same default values (SGX_MODE=SIM SGX_DEBUG=1).
The most common build settings are listed below.

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

When the build is successful, all executable binaries will be found in the "bin" directory.


Running the Demo Client
-----------------------

Before running, install the SGX driver and PSW for Linux* OS.
(This is also required to run the Pelz server.)

To run the demo client, execute `./bin/appinitiator`

Note: The client will not work properly if run outside of the "attestation_demo" directory.
E.g. the command `attestation_demo/bin/appinitiator` will not work properly.
This is consistent with the behavior of the pelz and pelz-service binaries.
