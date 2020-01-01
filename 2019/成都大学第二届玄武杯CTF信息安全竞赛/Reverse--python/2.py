
print("Plase input your flag:")
b=b'\x65\x6f\x62\x64\x78\x60\x67\x76\x70\x66\x60\x5c\x71\x66\x60\x31\x5c\x66\x62\x70\x7a\x7e'
a= input()
a=a.encode()
c=''
for i in a:
	#print(i)
	c=c+chr(i^3)
#print(c)

if(c.encode()==b):
	print("youare right:")
	print(a)
else:
	print("wrong!")