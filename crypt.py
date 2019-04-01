

#!/usr/bin/env python

import pyAesCrypt
import os
import getpass
import sys
import argparse



def cryptHelper(fileName, do):
        while True:
            newFile = input("Name or absolute Path for {0}ed file: ".format(do))
            if not os.path.isfile(newFile):
                return newFile
            else:
                print("Name exists. Please enter a new name")


def encrypt(fileName, password, bufferSize):
    # encrypt

    newFile = cryptHelper(fileName, "encrypt")
    pyAesCrypt.encryptFile(fileName, newFile, password, bufferSize)
    return newFile


def decrypt(fileName, password, bufferSize):

    # decrypt
    newFile = cryptHelper(fileName, "decrypt")
    pyAesCrypt.decryptFile(fileName, newFile, password, bufferSize)
    return newFile

def checkArgument(fileName):
    if not os.path.isfile(fileName):
        print("No valid file selected!")
        exit(0)
    else:
        try:
            return getpass.getpass()
        except Exception as error:
            print('ERROR', error)


def main():
# Parse arguments
    parser = argparse.ArgumentParser(description="Encrypt file with AES CBC")
    parser.add_argument('-e', '--encrypt', action="store", help="Name or absolute Path of file to encrypt")
    parser.add_argument('-d', '--decrypt', action="store", help="Name or absolute Path of file to decrypt")
    args = parser.parse_args()
    # Check argument
    if not len(sys.argv) > 1:
        print("You have to pass an argument.")
        return
    # encryption/decryption buffer size - 64K
    bufferSize = 64 * 1024
    try:
        if args.encrypt:
            password = checkArgument(args.encrypt)
            newFile = encrypt(args.encrypt, password, bufferSize)
        if args.decrypt:
            password = checkArgument(args.decrypt)
            newFile = decrypt(args.decrypt, password, bufferSize)
    except ValueError as error:
        print(error)
        sys.exit()
    print("{} created!".format(newFile))
    sys.exit(0)

if __name__ == "__main__":
    while True:
        try:
            main()
        except KeyboardInterrupt:
            print('\nInterrupted by human...')
            sys.exit(0)
