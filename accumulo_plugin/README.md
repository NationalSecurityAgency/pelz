# Pelz Plug-in for Accumulo

## Introduction
The pelz plug-in for Accumulo is an example of how to could integrate pelz into a crypro service.

Currently, the plug-in (PelzCryptoService) takes the AESCryptoService, provided by the Accumulo Crypto Module, and changes how the code handles the encryption of the File Encryption Key (FEK). This encryption is an AES wraping of the FEK with a Key Encryption Key (KEK).

The current differences between PelzCryptoService and the AESCryptoService are listed below:
1. Socket creation and management
2. Socket message creation and handling
3. Modify crypto proporties to refelect the PelzCryptoService
4. Requesting pelz to wrap/unwrap the FEK with identified KEK

Accumulo test code was added to ensure the proper working of the PelzCryptoService within Accumulo.
