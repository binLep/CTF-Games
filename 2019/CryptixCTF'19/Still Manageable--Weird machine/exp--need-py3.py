# This problem needs Python3
import string
import random

str_sed = '000010010101110100011000010100110011110101100010011000000001111100110101'\
          '011000110101010100110100010010110101101001010101001101100110110000111100'\
          '011000010001111000001011000011010000100000000001010101100011100000100101'
list_sed = []
alphanum = string.ascii_letters + string.digits

for i in range(0, len(str_sed), 8):
    list_sed.append(int('0b' + str_sed[i: i + 8], 2))


def check(str_res):
    for j in str_res:
        if ord(j) < 32 or ord(j) > 127:
            return False
    return True


def brute_force(rand_seed):
    global list_sed
    global alphanum
    rand_string = ''
    message = ''
    random.seed(rand_seed)
    for j in range(len(list_sed)):
        rand_string += alphanum[random.randint(1, 1000) % len(alphanum)]
    for j in range(len(list_sed)):
        message += chr(list_sed[j] ^ ord(rand_string[j]))
    # print('[\033[0;32m+\033[0m]num ' + str(rand_seed) + ' :' + message)
    return message


for i in range(0, 10001):
    try:
        res = brute_force(i)
        if check(res):
            print('[\033[0;32m+\033[0m]flag is ' + res)
    except:
        pass
        # print('[\033[0;31m-\033[0m]There is something wrong')
