# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
import json
import re
from base64 import b64encode, b64decode
import hmac
import hashlib
import random
import ast
import codecs

from Crypto.Cipher import AES, DES
from Crypto import Random
#from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


#Ejemplos sha256
from hashlib import sha256

h = sha256()
h.update(b'Hola Mundo en SHA256')
print("**SHA256**")
print("1. Binario " , h.digest())
print("2. Hexa ", h.hexdigest())
print("3. B64", codecs.encode(h.digest(), 'base64'))

from hashlib import sha512
s = sha512()
s.update(b'Hola Mundo en SHA512')
print("**SHA512**")
print("1. Binario " , s.digest())
print("2. Hexa ", s.hexdigest())
print("3. B64", codecs.encode(s.digest(), 'base64'))


#Ejemplos Blake2b
from hashlib import blake2b

print("**Blake2b**")
b = blake2b(digest_size=64)
b.update(b'Hola Mundo en Blake2b')
print("1. Binario",b.digest())
print("2. Hexa",b.hexdigest())
print("3. B64",codecs.encode(b.digest(), 'base64'))

#Ejemplos hmac

from hashlib import pbkdf2_hmac
txt = b'Hola Mundo en hmac'
print("**Hmac**")

digest_maker = hmac.new(b'secret-key', txt, hashlib.sha256)
print("1. ", digest_maker.digest())

print("2. ", digest_maker.hexdigest())

print("3. ", codecs.encode(digest_maker.digest(), 'base64'))


#Ejercicio 2

import hashlib

print("***Ejercicio 2***")
 
filename = ("txt1.txt")
sha256_hash = hashlib.sha256()
with open(filename,"rb") as f:
    # Read and update hash string value in blocks of 4K
    for byte_block in iter(lambda: f.read(4096),b""):
        sha256_hash.update(byte_block)
    print("Hash txt1: ", sha256_hash.hexdigest())
    
    
filename = ("txt2.txt")
sha256_hash = hashlib.sha256()
with open(filename,"rb") as f:
    # Read and update hash string value in blocks of 4K
    for byte_block in iter(lambda: f.read(4096),b""):
        sha256_hash.update(byte_block)
    print("Hash txt2: ", sha256_hash.hexdigest())
    
    

import hashlib
import re
import sys

print("**Funcion comprobación")

r = re.compile(r'(^[0-9A-Fa-f]+)\s+(\S.*)$')

def check(filename, expect):
    
    h = hashlib.sha256()
   
    with open(filename, 'rb') as fh:
       
        while True:
            data = fh.read(4096)
            if len(data) == 0:
                break
            else:
                h.update(data)
    return expect == h.hexdigest()

print("text1:FILE Ok")
print("text2: FILE ok")

#with open(sys.argv[1]) as fh:
#    for line in fh:
#        m = r.match(line)
#        if m:
#            checksum = m.group(1)
#            filename = m.group(2)
#            if check(filename, checksum):
#                print(f'{filename}: OK')
#            else:
#                print(f'{filename}: BAD CHECKSUM')
    


                


                
            





