import random

def addPadding(self):  # Add padding to the datas using PKCS5 spec.#PKCS5 ->https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    pad_len = 8 - (len(self) % 8) #find how many bytes of padding you need to add so each block can be multiple of 8
    if(pad_len!=8):    
        self += pad_len * chr(pad_len) #add pad_len times the unicode character of the pad_len to the text
    return self

def removePadding(self):  # Remove the padding of the plain text (it assumes there is padding)
    pad_len = ord(self[-1]) #integer representing the Unicode character of last element because padding is added in the end of the string
    if pad_len in range(1,8): # check if Unicode code point of last element matches with one of the padding's code points
        return self[:-pad_len] #epestrese ta stoixia mexri ektos toy padding
    else:
        return self 

# Permute function to rearrange the bits
def permute(k, arr, n):
    permutation = ""
    for i in range(n):
        permutation = permutation + k[arr[i] - 1] #loop through output elements in order(keyp)
    return permutation # returns class str object 


# calculating xor of two strings of binary number a and b
def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans


# Table of Position of 64 bits at initail level: Initial Permutation Table
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

# Expansion D-box Table
exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutaion Table
per = [16, 7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2, 8, 24, 14,
       32, 27, 3, 9,
       19, 13, 30, 6,
       22, 11, 4, 25]

# S-box Table
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final Permutaion Table
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

# --parity bit drop table drops bits 8,16,24,32 etc and permutes the rest
keyp = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# Number of bit shifts (for 1,2,9,16 rounds - 1 bit shift the rest 2)
shift_table = [1, 1, 2, 2,
               2, 2, 2, 2,
               1, 2, 2, 2,
               2, 2, 2, 1]

# Key- Compression Table : Compression of key from 56 bits to 48 bits
key_comp = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32]


def encrypt(pt, rkb):
    #The zfill() method adds zeros (0) at the beginning of the string, until it reaches the specified length.
    pt = bin(int(pt, 16))[2:].zfill(len(pt)*4) 
    #int(pt, 16) - convert the string to decimal knowing its hex inside the string and then convert the integer to binary string bin()
    # remove the 0b prefix and fill with zeros in the beginning if needed to reach 64=16*4 since each hex number is 4 bits

    print("before", pt)
    # Initial Permutation
    pt = permute(pt, initial_perm, 64)
    print("After inital permutation", hex(int(pt, 2)).replace("0x", ""))

    # Splitting
    left = pt[0:32]
    right = pt[32:64]
    for i in range(16): #rounds
        # Expansion D-box: Expanding the 32 bits data into 48 bits
        right_expanded = permute(right, exp_d, 48)

        # XOR RoundKey[i] and right_expanded
        xor_x = xor(right_expanded, rkb[i])

        # S-boxes: substituting the value from s-box table by calculating row and column
        sbox_str = ""
        for j in range(8): # j chooses a S-box table from the 8 tables
            row = int(xor_x[j * 6] + xor_x[j * 6 + 5],2) # bits 1 and 6 of the group of 6 bits choose line of S-box (index:0,5)
            col = int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4],2) #bits 2,3,4,5 choose column
            val = sbox[j][row][col] 
            sbox_str = sbox_str + bin(val).replace("0b","").zfill(4)
            # convert val to binary - remove prefix and fill with 0s at the beginning of the binary string in order to get 4 bits 
            
        # Straight D-box: After substituting rearrange the bits
        sbox_str = permute(sbox_str, per, 32)

        # XOR left and sbox_str
        result = xor(left, sbox_str)
        left = result

        # Swapper
        if (i != 15): # left, right parts don't swap in the last round
            left, right = right, left
        print("Round ", i + 1, " ", hex(int(left, 2)).replace("0x", "").zfill(8), " ", hex(int(right, 2)).replace("0x", "").zfill(8))

    # Combination
    combine = left + right

    # Final permutaion: final rearranging of bits to get cipher text
    cipher_text = permute(combine, final_perm, 64)
    return cipher_text # class str = cipher text in binary form of 64 bits
# ================================================== DRIVER CODE ================================================== #
# ========== Set plaintext ========== #
# set plaintext to be encrypted
pt="hello world!"

# ========== Padding ========== #
# add padding so text is multiple of 8 (char = 1 byte - 8 bytes * 8 bits = 64 bits = 1 cipher block)
pt = addPadding(pt).encode("utf-8").hex()
# encode method converts string (stored as Unicode) into bytes
# hex method converts bytes to hex
# strings stored as Unicode means that the string is a sequence of Unicode code points
# code point = integer value that uniquely identifies a character

# ========== Split plaintext to blocks ========== #

data=[] # empty list 
# (len(pt)) - how many hex digits contains the pt
# pt before padding = 11 chars = 11 bytes
# 16 bytes after padding = 32 hex digits 
# len(pt)/16 = double format range needs int
for i in range(int(len(pt)/16)):
    # every digit in hex value is 4bits in decimal 16*4=64 so it breaks the string to 64bit blocks
    data.append(pt[i*16:(i+1)*16]) # splits hex digits of pt into groups of 16
print("64 bit blocks:", data)

# ========== Set key ========== #
key = '%016x' % random.randrange(16**16)  #random key in hex value but as a string 16^16 γιατι 16 ψηφια οποτε θελουμε να μπορει να παρει ολες τις τιμες
print(key)
# key length = 64 bits = 16 hex digits

# ========== Key generation ========== #
key = bin(int(key, 16))[2:].zfill(64)  # removing the first 2 digits 0b which simlpy indicate that our number is binary
# bin returns binary representation of an integer

# getting 56 bit key from 64 bit removing the parity bits
key = permute(key, keyp, 56)

# Splitting key
left = key[0:28]  
right = key[28:56] 

rkb = [] # rkb for RoundKeys in binary

for i in range(16): # for every round
    # Shifting the bits by nth shifts by checking from shift table
    left = left[shift_table[i]:]+left[:shift_table[i]] # start from 1: or 2: and add the remaining digits at the end :1 or :2
    right = right[shift_table[i]:]+right[:shift_table[i]]

    # Combination of left and right string
    combine_str = left + right

    # Compression of subkey from 56 to 48 bits
    round_key = permute(combine_str, key_comp, 48)

    rkb.append(round_key)

    # function hex() converts integer to hex

# ========== Encryption ========== # 
cipher_text = []   
# data=list - contains groups of 16 hex digits (str)
for i in range(len(data)): # for every 64bit block ->every element of data is a block
    print("Encryption")
    cipher_text.append(hex(int(encrypt(data[i], rkb), 2)).replace("0x", "").zfill(16)) # append the encrypted data blocks
    print("Cipher Text : ", cipher_text[i])

# ========== Decryption ========== #
print("Decryption")
rkb_rev = rkb[::-1] # reverse roundkey lists

text= []
for i in range(len(data)):
    # cipher_text is in form of binary string - 64 bits
    text.append(hex(int(encrypt(cipher_text[i], rkb_rev), 2)).replace("0x", "").zfill(16)) # append the decrypted data blocks
    text[i]=bytearray.fromhex(text[i]).decode('utf8')
    print("Plain Text of  block ", i+1, ": ", text[i])
final = "".join(text)  # joining the decrypted data blocks in one string
print("Plain Text with padding : ", final)  # final decrypted message, padding not removed
final = removePadding(final)
print("Plain Text : ", final)  # final decrypted message, padding removed
