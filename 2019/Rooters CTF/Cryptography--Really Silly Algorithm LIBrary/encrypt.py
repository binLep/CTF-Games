#!/usr/bin/env python3

from Crypto.Util.number import *
import gmpy2, binascii
from sillyLibrary import rsalib_p, rsalib_q
from secret import flag

n = rsalib_p*rsalib_q

e = 0x10001

ciphertext = binascii.hexlify(long_to_bytes(pow(bytes_to_long(flag), e, n)))

file = open('flag.enc', 'w')

file.write("ciphertext: {}\nn: {}\ne: ".format(ciphertext, str(n), str(e)))