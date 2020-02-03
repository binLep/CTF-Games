#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gmpy2
import binascii

p = gmpy2.mpz(681782737450022065655472455411)
q = gmpy2.mpz(675274897132088253519831953441)
n = p * q
e = gmpy2.mpz(13)
phi_n = (p - 1) * (q - 1)
d = gmpy2.mpz(gmpy2.invert(e, phi_n))  # 求逆元
c = gmpy2.mpz(275698465082361070145173688411496311542172902608559859019841)
m = pow(c, d, n)
m_hex = hex(m)[2:]
print "ascii:\n%s"%(binascii.a2b_hex(m_hex).decode("utf8"))
