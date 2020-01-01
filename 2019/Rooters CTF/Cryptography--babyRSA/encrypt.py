#!/usr/bin/env python3

from Crypto.Util.number import *
import gmpy2, binascii
from secret import flag

p = getPrime(128)
q = getPrime(128)

n = p*q
e = 65537

encryptedFlag = bytes_to_long(flag)
encryptedFlag = pow(encryptedFlag, e, n)
encryptedFlag = binascii.hexlify(long_to_bytes(encryptedFlag))

file = open("flag.enc", 'w')

file.write("ciphertext: {}\nn: {}\ne: {}".format(encryptedFlag, str(n), str(e)))

file.close()
