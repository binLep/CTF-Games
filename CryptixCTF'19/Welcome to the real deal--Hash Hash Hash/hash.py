import random
from math import sqrt
from primes import random_prime '''Gives us a random prime for hashing'''
from mymessages import a_secret 

def hash_it(data, prime):
    hashed_number = 0
    sum_key = ord(data) + prime
    mul_key = ord(data)*prime
    numerator = ord(data)**2 + prime**2 + sum_key**2 + mul_key**2
    denominator = sqrt(ord(data)) + sqrt(prime) + sqrt(sum_key) + sqrt(mul_key)
    hashed_number = int(sqrt(numerator/denominator))
    return hex(hashed_number)


True_hash = ''
for i in a_secret:
    True_hash += hash_it(i, random_prime) + ":"
print(True_hash)
