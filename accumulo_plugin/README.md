# Pelz Plug-in for Accumulo

## Introduction
The pelz plug-in for Accumulo is an example of how to integrate pelz with an application handling and/or processing encrypted data (in the case of Accumulo, this application is a distributed database). 

**Note: This plug-in is a proof of concept and is not intended for operational use. Further, it is not yet fully implemented.**

Accumulo implements data encryption/decryption functionality via its "pluggable" [CryptoService](https://accumulo.apache.org/docs/2.x/security/on-disk-encryption) Java interface. It distributes a "default" implementation named AESCryptoService. This plug-in (PelzCryptoService) provides an alternative CryptoService implementation.

Compared to the reference AESCryptoService, included with the Accumulo Crypto Module, this plug-in changes how the code handles encryption of the File Encryption Key (FEK) by using pelz for the AES Key Wrap. PelzCryptoService employs pelz key wrapping/unwrapping services in place of a standard cryptographic library. Most importantly, this pelz-based approach constrains both the Key Encryption Keys (KEKs), used to wrap/unwrap FEKs, and the unwrapped FEKs, used to encrypt/decrypt data, within the pelz trusted execution environment (TEE).

The differences between PelzCryptoService and the AESCryptoService can be summarized as: 

1. PelzCryptoService adds socket creation and management features.
2. PelzCryptoService adds socket message creation and handling functionality. 
3. PelzCryptoService modifies some parameters and/or properties in accordance with the cryptographic protocol specified for the revised approach. 
4. PelzCryptoService utilizes the pelz application programming interface (API) to wrap/unwrap the FEK with an identified KEK.

Accumulo test code was added to ensure that the PelzCryptoService correctly and fully implements Accumulo data encryption/decryption functionality. 
