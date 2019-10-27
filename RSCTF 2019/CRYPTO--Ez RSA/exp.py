#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gmpy2
import binascii
from Crypto.Util import *

p = gmpy2.mpz(23802298000094034769309134046892260326665858038920881101172459)
q = gmpy2.mpz(2663993)
n = gmpy2.mpz(63409155256164507967196147936982653264415559154678954807355722568787)
e = gmpy2.mpz(5)
phi_n = (p - 1) * (q - 1)
d = gmpy2.mpz(gmpy2.invert(e, phi_n))  # 求逆元
c = gmpy2.mpz(47227268354772263297672801857404286345600006178682788542814788330438)
m = pow(c, d, n)
print number.long_to_bytes(m).encode('hex')
print 'This is fake flag --> ' + binascii.a2b_hex(hex(m)[2:]).decode("utf8")
