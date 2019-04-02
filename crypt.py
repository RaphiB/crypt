

#!/usr/bin/env python

import pyAesCrypt
import os
import getpass
import sys
import argparse


def encrypt(fileName, outputFile, password, bufferSize):
    # encrypt
    pyAesCrypt.encryptFile(fileName, outputFile, password, bufferSize)
    return outputFile

def decrypt(fileName, outputFile, password, bufferSize):
    # decrypt
    pyAesCrypt.decryptFile(fileName, outputFile, password, bufferSize)
    return outputFile

def checkArguments(inputFile, newFile):
    isFile(inputFile)
    alreadyExists(newFile)
    try:
        return getpass.getpass()
    except Exception as error:
        print('ERROR', error)

def isFile(fileName):
    if not os.path.isfile(fileName):
        print("\"{0}\" can't be found or isn't a file!".format(fileName))
        exit(0)


def alreadyExists(fileName):
    if os.path.isfile(fileName):
        print("\"{0}\" already exists.".format(fileName))
        if input("Do you want to replace the existing file? yes/no: ").lower().startswith("y"):
            return
        exit(0)




def main():
# Parse arguments
    parser = argparse.ArgumentParser(description="Encrypt file with AES CBC")
    parser.add_argument('-e', '--encrypt', action="store", nargs=2, help="Name or absolute Path of file to encrypt and output file")
    parser.add_argument('-d', '--decrypt', action="store", nargs=2, help="Name or absolute Path of file to decrypt and output file")
    args = parser.parse_args()
    # Check argument
    if not len(sys.argv) > 1:
        print("You have to pass an argument. Insert -h for more information.")
        sys.exit(0)
    # encryption/decryption buffer size - 64K
    bufferSize = 64 * 1024
    try:
        if args.encrypt:
            fileToEncrypt, outputFile = args.encrypt
            password = checkArguments(fileToEncrypt, outputFile)
            newFile = encrypt(fileToEncrypt, outputFile, password, bufferSize)
        if args.decrypt:
            fileToDecrypt, outputFile = args.decrypt
            password = checkArguments(fileToDecrypt, outputFile)
            newFile = decrypt(fileToDecrypt, outputFile, password, bufferSize)
    except ValueError as error:
        print(error)
        sys.exit(0)
    print("{} created!".format(newFile))
    sys.exit(0)

if __name__ == "__main__":
    while True:
        try:
            main()
        except KeyboardInterrupt:
            print('\nInterrupted by human...')
            sys.exit(0)
