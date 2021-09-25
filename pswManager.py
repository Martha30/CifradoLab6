# Universidad del Valle de Guatemala
# Cifrado de informacion
# Hugo Roman 19199
# Laurelinda Gomez 19501
# Juan Pablo Pineda 19087
# laboratorio 7

import hashlib
import hmac
import os
import getpass

def registro(u, c):
    try:
        with open('base.txt', 'a') as doc:
            salt = os.urandom(hashlib.blake2b.SALT_SIZE)
            process = hashlib.pbkdf2_hmac("sha512", str.encode(c), salt, 100)
            hashed = process.hex()
            doc.write(u + " " + salt.hex() + " " + hashed + "\n")
            return True
    except OSError:
        print("Failed, try again ")

def login(u, c):
    try:
        with open('base.txt', 'r') as data:
            lines = data.read().splitlines()
            for l in lines:
                singleLine = l.split(" ")
                if(u == singleLine[0]):
                    salt = bytes.fromhex(singleLine[1])
                    process = hashlib.pbkdf2_hmac("sha512", str.encode(c), salt, 100)
                    hashed = process.hex()
                    if(hashed == singleLine[2]):
                        return True
                    else:
                        return False
    except OSError:
        print("Failed, try again ")


decision = input("welcome to the system would you like to:\n1. Register\n2. Login \n")
if decision == '1':
    username = input("Please enter Your new username ")
    password = getpass.getpass("please enter your new password ")
    if(registro(username, password) == True):
        print("register Successful ")
if decision == '2':
    username = input("Please enter your username ")
    password = getpass.getpass("please enter your password ")
    if(login(username, password) == True):
        print("Login Successful ")
    else:
        print("login failed")
