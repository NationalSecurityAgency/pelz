#!/bin/bash

# Register keys with the pykmip server
python3 -c "
from kmip import enums
from kmip.pie import client
from kmip.pie import objects

c = client.ProxyKmipClient()

symmetric_key = objects.SymmetricKey(
     enums.CryptographicAlgorithm.AES,
     256,
     (
         b'\x00\x01\x02\x03\x04\x05\x06\x07'
         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
         b'\x00\x01\x02\x03\x04\x05\x06\x07'
         b'\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
     )
 )

with c:
    for i in range(10):
        key_id = c.register(symmetric_key)
        print(f'Registered new key with ID {key_id}')
"
