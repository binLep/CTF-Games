#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

str_res = ''
for i in range(1, 1000):
    process_name = './' + str(i).rjust(3, '0') + '.c.out'
    for j in range(33, 127):
        flag = True
        while True:
            try:
                p = process(process_name)
                p.sendlineafter('What is my character?\n', chr(j))
                res = p.recv()
                if res == 'OK!\n':
                    str_res += chr(j)
                    success('str_res = ' + str_res + '(' + process_name + ')')
                    flag = False
                elif res == 'Nope!\r\n':
                    info(str(j).rjust(3, '0') + " doesn\'t belong to process " + process_name)
                else:
                    warning('No match')
                p.close()
                break
            except:
                warning('There is a problem......')
                pass
        if flag is False:
            break

print str_res
p.interactive()

