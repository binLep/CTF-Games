import random
import string
from deep_memory import message

print("Encrpyt everything!!.... Oh no, system failure. Encrypting last message received")

rand = random.randint(1,10000)
alphanum = string.ascii_letters + string.digits

def random_string(rand_seed, message):
    random.seed(rand_seed)
    rand_string = ''
    for i in range(len(message)):
        rand_string += alphanum[random.randint(1,1000)%len(alphanum)]
    return rand_string

def encrpyt(random_str, message):
    encrpyted = ''
    for i in range(len(message)):
        k = ord(message[i])^ord(random_str[i])
        encrpyted += (bin(k)[2:]).zfill(8)
    return encrpyted

print(encrpyt(random_string(rand, message), message))


