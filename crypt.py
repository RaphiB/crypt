#!/usr/bin/env python

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os, random, sys
import getpass
import argparse


"""Validates file names and prompts for password """
def checkArguments(inputFile, newFile):
    checkFile(inputFile, True)
    checkFile(newFile, False)
    try:
        return getpass.getpass()
    except Exception as error:
        print('ERROR', error)

def getKey(password):
        hasher = SHA256.new(password.encode())
        return hasher.digest()

"""Takes file names and checks if they can be used correctly """
def checkFile(fileName, bol):
    if bol:
        if not os.path.isfile(fileName):
                print("\"{0}\" can't be found or isn't a file!".format(fileName))
                exit(0)
    else:
        if os.path.isfile(fileName):
                 print("\"{0}\" already exists.".format(fileName))
                 if input("Do you want to replace the existing file? yes/no: ").lower().startswith("y"):
                    return
                 exit(0)


"""Takes arguments and validates them. Returns checked arguments"""
def passArguments(crypt):
    inputFile, outputFile = crypt
    password = checkArguments(inputFile, outputFile)
    return inputFile, outputFile, password

def encrypt(key, filetoEncrypt, outputFile, bufferSize):
    filesize = str(os.path.getsize(filetoEncrypt)).zfill(16)
    IV = os.urandom(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filetoEncrypt, "rb") as infile:
        with open(outputFile, "wb") as outfile:
            outfile.write(filesize.encode())
            outfile.write(IV)
            while True:
                chunk = infile.read(bufferSize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += str.encode(" "*(16-(len(chunk) % 16)))
                outfile.write(encryptor.encrypt(chunk))

def decrypt(key, filetoDecrypt, outputFile, bufferSize):
    with open(filetoDecrypt, "rb") as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)
        with open(outputFile, "wb") as outfile:
            while True:
                chunk = infile.read(bufferSize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)

def main():
# Parse arguments
    parser = argparse.ArgumentParser(description="Encrypt file with AES-256-CBC")
    parser.add_argument('-e', '--encrypt', action="store", nargs=2, help="Name or absolute Path of file to encrypt and output file")
    parser.add_argument('-d', '--decrypt', action="store", nargs=2, help="Name or absolute Path of file to decrypt and output file")
    args = parser.parse_args()
    # Check argument
    if not len(sys.argv) > 1:
        print("You have to pass an argument. Insert -h for more information.")
        sys.exit(0)
    # encryption/decryption buffer size - 64K
    bufferSize = 64 * 1024
    # make initialization vector
    try:
        if args.encrypt:
            fileToEncrypt, outputFile, password = passArguments(args.encrypt)
            key = getKey(password)
            # encrypt
            encrypt(key, fileToEncrypt, outputFile, bufferSize)
        if args.decrypt:
            fileToDecrypt, outputFile, password = passArguments(args.decrypt)
            key = getKey(password)
            # decrypt
            decrypt(key, fileToDecrypt, outputFile, bufferSize)
    except ValueError as error:
        print(error)
        sys.exit(0)
    print("{} created!".format(outputFile))
    sys.exit(0)

if __name__ == "__main__":
    while True:
        try:
            main()
        except KeyboardInterrupt:
            print('\nInterrupted by human...')
            sys.exit(0)
