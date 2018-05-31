#!/bin/env python
from Crypto.Cipher import AES
from Crypto import Random
import binascii

key=[240, 51, 28, 224, 38, 106, 218, 206, 134, 168, 161, 59, 250, 20, 103, 64]
msg=[0x13,0x37,0x69,0x42,0x13,0x37,0x69,0x42,0x13,0x37,0x69,0x42,0x13,0x37,0x69,0x42]

key=bytes(key)
msg=bytes(msg)

cipher = AES.new(key, AES.MODE_ECB)
c = cipher.decrypt(msg)
print(binascii.hexlify(c))
