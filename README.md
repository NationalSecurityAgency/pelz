# Pelz

## Introduction
Pelz is an open source project about managing keys within a service for other applications. Currently, pelz provides the ability to load keys which can then be used to wrap or unwrap other keys (or data). The key table and wrapping/unwrapping functionality is implemented within an Intel Software Guard eXtensions (SGX) trusted-execution environment. This means that the pelz encryption/decryption operations, and the cryptographic keys employed, can be obscured even from the operating system and privileged users that administer the system. Further, pelz functionality can be hosted on commodity (non-specialized) computing platforms. 

Pelz provides a socket interface to other programs to request AES key wrap/unwrap.  The request and response are JavaScript Object Notation (JSON) formatted. The expected JSON structure is described below. The location of key encryption keys (KEKs) is specified through a URI. The URI can identify a file, a key server destination, etc. The schemes currently implemented are specified below.

Note: Pelz is a proof of concept and does not have all the security features required in a robust tool for operational use. Further, in its current prototyping phase, the application programming interface (API) is still somewhat fluid but should stabilize as fundamental capabilities mature. There are no plans for creating a release at this time.
----

## Running pelz as a Linux service
The source code comes with a script that establishes pelz as a Linux service running in the background. Instructions can be found in the [INSTALL](INSTALL.md).

## Running the pelz Accumulo plugin  
The source code comes a script to install or uninstall the java files required to build the PelzCryptoService with Apache Accumulo. Instruction can be found in the [INSTALL](install.md).
Pelz has been tested against Apache Accumulo commit a1a1b72.

## Installing Kmyth to run pelz
Pelz has been tested against Kmyth commit 246a5c2.

----

## Data formats
This section describes the expected certificate, JSON and URI formats.

### Certificate File Format
The certificates used for load cert/private are expected to be converted to a DER format before being sealed.

### JSON Key and Value List
The JSON objects can be in two forms: requests and responses.  

#### Request JSON Key and Values
* request_type : int
    * 1 for AES Key Wrap (unsigned JSON request)
    * 2 for AES Key Unwrap (unsigned JSON request)
    * 3 for AES Key Wrap (signed JSON request) - still being implemented
    * 4 for AES Key Unwrap (signed JSON request) - still being implemented
* key_id : string of characters
     * URI for the key location - used as the key identifier.
     * URI syntax must currently comply with RFC 8089 and RFC 1738 Section 3.1.
* data : string of characters
    * Base64 encoded data to be processed based on request type.

Examples:

JSON Request for AES Key Wrap
* {"key_id": "file:~/pelz/test/key1.txt", "request_type": 1, "data": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n"}
* {"key_id": "pelz://localhost/7000/fake_key_id", "request_type": 1, "data": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n"}

JSON Request for AES Key Unwrap
* {"key_id": "file:~/pelz/test/key1.txt", "request_type": 2, "data": "BtIjIgvCaVBwUi5jTOZyIx2yJamqvrR0BZWLFVufz9w=\n"}
* {"key_id": "pelz://localhost/7000/fake_key_id", "request_type": 2, "data": "BtIjIgvCaVBwUi5jTOZyIx2yJamqvrR0BZWLFVufz9w=\n"}

#### Response JSON Key and Values
* key_id : string of characters
    * URI for the key location (key identifier).
    * The key_id specified in the JSON request will be included in the JSON response.
* data : string of characters
    * Base-64 encoded, output data based on request type.
* error : string of characters
    * Error message for the service user

Examples:
* {"key_id": "file:~/pelz/test/key1.txt", "enc_out": "BtIjIgvCaVBwUi5jTOZyIx2yJamqvrR0BZWLFVufz9w=\n"}
* {"key_id": "file:~/pelz/test/key1.txt", "dec_out": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n"}
* {"error': "Key not added"}

### URI Schemes
Although any URI scheme could be supported, we currently only support reading from a filesystem or FTP.

#### File
* Retrieve a key from the local host at the location provided by URI.
* RFC 8089 (File Scheme) based sytax.

#### Pelz 
* Retrieve a key from a networked server.
* RFC 1738 (Uniform Resource Locators) Section 3.1 based syntax. No specific application of the protocol sections for RFC959 (FTP).
* This implementation assumes user and password are included into host if applicable.
