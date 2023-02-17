# Pelz Plug-in for Accumulo

## Introduction
The existing pelz plug-in for Accumulo, the PelzCryptoService, is an example of how to integrate pelz with an application handling and/or processing encrypted data (in the case of Accumulo, this application is a distributed database). 

**Note: This plug-in is a proof of concept and is not intended for operational use. Further, it is not yet fully implemented.**

Accumulo implements data encryption/decryption functionality via its "pluggable" [CryptoService](https://accumulo.apache.org/docs/2.x/security/on-disk-encryption) Java interface. It distributes a "default" implementation named AESCryptoService. This PelzCryptoService (also referred to as the pelz plug-in) provides an alternative CryptoService implementation.

Compared to the reference AESCryptoService, included with the Accumulo Crypto Module, this plug-in changes how the code handles encryption of the File Encryption Key (FEK) by using pelz for the AES Key Wrap with a Key Encryption Key (KEK). PelzCryptoService employs pelz key wrapping/unwrapping services in place of a standard cryptographic library.

The differences between PelzCryptoService and the AESCryptoService can be summarized as: 

1. PelzCryptoService adds socket creation and management features.
2. PelzCryptoService adds socket message creation and handling functionality. 
3. PelzCryptoService modifies some parameters and/or properties in accordance with the cryptographic protocol specified for the revised approach. 
4. PelzCryptoService utilizes the pelz application programming interface (API) to wrap/unwrap the FEK with an identified KEK.

Accumulo test code was added to ensure that the PelzCryptoService correctly and fully implements Accumulo data encryption/decryption functionality. This is the current plug-in option and will continue to be one of the plug-n options going forward.

## Way Forward
The current plug-in is completely in Java and only protects the KEK. Going forward, we would want to add an option to allow the plug-in to use a SGX enclave, also known as a trusted execution environment (TEE). The SGX enclave or plug-in enclave would protect the FEKs within a secure environment in the same way pelz protects the KEKs. This pelz-based approach constrains both the KEKs, used to wrap/unwrap FEKs, and the unwrapped FEKs, used to encrypt/decrypt data, within an enclave environment.  This approach outlined in the way forward would be the second install option for the plug-in.

To protect the FEK, we will need to move the following portions of the code to the plug-in encalve:

1. Creation of the FEK
2. Encryption/decryption of files with the FEK
3. Utilizing enclave local attestation to securely request to wrap/unwrap the FEK with identified KEK

Along with these portions of code moving to C, the Java code will also have the below changes:

1. Removing the socket creation and management features
2. Removing the socket message creation and handling functionality
3. Removing encryption and decryption functions 
4. Adding JNI code to pass file data streams and variables to and from C

### Java Code Changes
The current java code for the plug-in could be streamlined by removing the following code files:

1. PelzClientSocket.java
2. PelzKeyUtils.java
3. PelzObjects.java

These files are used for the socket creation, management, and message handling functionality which will no longer be needed. This should be replaced with JNI code to pass the java file stream and other variable data to the C code.

PelzCryptoService.java will have the most changes. The encryption and decryption functions within the file will need to be stripped and replaced with the new JNI code for encryption and decryption. Along with the CryptoSevice changes, the pelz Accumulo test files will need to be updated to reflect the changes to PelzCryptoService.java.

### C Enclave Code
The enclave code will be broken into two aspects just like the pelz code; the untrusted and trusted C code. The untrusted code will be where the corresponding JNI code will be to get the file data stream and other variables into the C code and pass the processed data back to the Java code. After passing the data into the enclave, the enclave is where most of the data will be processed.

Most of the code needed for the plug-in enclave is available and would only need to be organized into a new enclave build. The new portion of code that would need to be written would be the untrusted  JNI interface to the Java code.

List of the already written code to be add to the plug-in build code base:

1. All of the cipher code
2. Local attestation request code
3. charbuf.c

