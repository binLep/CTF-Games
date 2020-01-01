import base64
cipher = "JiwhJzshc3lyeXZwdHJxeXFzcXZ1cXl3eHR1JnN0IiZ1JHEheD0="
cipher = base64.b64decode(cipher)
flag = ""

for i in range(len(cipher)):
    flag += chr(64 ^ ord(cipher[i]))
print flag
