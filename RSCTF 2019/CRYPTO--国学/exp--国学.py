import binascii

int_dec = '25744171658477746764476868146373648433826484277866842131686'
int_dec = list(int_dec)
for i in range(0, len(int_dec)):
    int_dec[i] = str(int(int_dec[i]) - 1)
int_oct = int(''.join(int_dec))
int_dec = int(str(int_oct), 8)
int_hex = hex(int_dec)
print binascii.a2b_hex(int_hex[2:-1]).decode("utf-8")
