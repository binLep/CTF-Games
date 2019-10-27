import base64
correct = 'KVEkKFRUUVQiJiUmIyglVlNVJShRViQnUSBVViUmU1Y='
flag = base64.b64decode(correct)
flag = list(flag)
for i in range(len(flag) - 1, -1, -1):
    flag[i] = chr(ord(flag[i]) - 16)
    flag[i] = chr(ord(flag[i]) ^ 32)
print 'flag{' + ''.join(flag) + '}'
