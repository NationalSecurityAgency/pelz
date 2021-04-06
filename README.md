# Pelz

## Introduction
Pelz is an open source project about managing keys within a service for other applications. Currently, pelz provides the ability to load keys which can then be used to wrap or unwrap other keys. It is our goal to move the key table and wrapping/unwrapping functionality into a trusted-execution environment.

Pelz provides a socket interface to other programs to request AES key wrap/unwrap.  The request and response are JavaScript Object Notation (JSON) formatted. The expected JSON structure is described below. The location of key encryption keys (KEKs) is specified through a URI. The URI can identify a file, a key server destination, etc. The schemes currently implemented are specified below.

Pelz is currently in an early prototyping phase. It is our intent to eventually move the key table into trusted hardware. There are no plans for creating a release at this time.
----

## Running pelz as a Linux service
The source code comes with a script that establishes pelz as a Linux service running in the background. Instructions can be found in the [INSTALL](INSTALL.md).

## Running the pelz Accumulo plugin  
The source code comes a script to install or uninstall the java files required to build the PelzCryptoService with Apache Accumulo. Instruction can be found in the [INSTALL](install.md).

----

## Data formats
This section describes the expected JSON and URI formats.

### JSON Key and Value List
The JSON objects can be in two forms: requests and responses.  

#### Request JSON Key and Values
* request_type : int
    * 1 for AES Key Wrap
    * 2 for AES Key Unwrap
* key_id : string of charaters
     * URI for the key location - used as the key identifier.
     * URI syntax must currently comply with RFC 8089 and RFC 1738 Section 3.1.
* key\_id_len : int
    * Integer specifying the length of the key_id URI.
* enc_data : string of charaters
    * Base64 encoded version of the unencrypted key to be AES Key Wrapped.
* enc\_data_len : int
    * Integer specifying the length of the base-64 encoded, unencrypted key.
* dec_data : string of charaters
    * Base-64 encoded version of the encrypted key to be AES Key UnWrapped.
* dec\_data_len : int
     * Integer specifying the length of the base-64 encoded, encrypted key.

Examples:

JSON Request for AES Key Wrap
* {"key_id": "file:~/pelz/test/key1.txt", "request_type": 1, "enc_data_len": 33, "key_id_len": 37, "enc_data": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n"}

JSON Request for AES Key Unwrap
* {"key_id": "file:~/pelz/test/key1.txt", "request_type": 2, "dec_data_len": 45, "key_id_len": 37, "dec_data": "BtIjIgvCaVBwUi5jTOZyIx2yJamqvrR0BZWLFVufz9w=\n"}

#### Response JSON Key and Values
* key_id : string of charaters
    * URI for the key location (key identifier).
    * The key_id specified in the JSON request will be included in the JSON response.
* key\_id_len : int
    * Integer specifying the length of the key_id URI.
* enc_out : string of charaters
    * Base-64 encoded, AES Key Wrapped key.
* enc\_out_len : int
    * Integer specifying the length of the base-64 encoded, encrypted key.
* dec_out : string of charaters
    * Base-64 encoded, AES Key UnWrapped key.
* dec\_out_len : int
    * Integer specifying the length of the base-64 encoded, unencrypted key.
* error : string of charaters
    * Error message for the service user

Examples:
* {u'key_id': u'file:~/pelz/test/key1.txt', u'enc_out': u'BtIjIgvCaVBwUi5jTOZyIx2yJamqvrR0BZWLFVufz9w=\n', u'key_id_len': 37, u'enc_out_len': 45}
* {u'key_id': u'file:~/pelz/test/key1.txt', u'dec_out': u'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4\n', u'key_id_len': 37, u'dec_out_len': 33}
* {u'error': u'Key not added'}

### URI Schemes
Although any URI scheme could be supported, we currently only support reading from a filesystem or FTP.

#### File
* Retrieve a key from the local host at the location provided by URI.
* RFC 8089 (File Scheme) based sytax.

#### FTP 
* Retrieve a key from a networked server (to be implemented as a future enhancement).
* RFC 1738 (Uniform Resource Locators) Section 3.1 based syntax. No specific application of the protocol sections for RFC959 (FTP).
* This implementation assumes user and password are included into host if applicable.
