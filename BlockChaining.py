import random
from hashlib import sha256
from Ciphers import Ceaser, Columnar

#if an encryption or decryption method returns null, then the key is invalid.

def encryptCaeser(plainText: str, key: int):
    random.seed(key)

    fileSignature = sha256(plainText.encode('utf-8')).hexdigest().encode('utf-8')  # signature of entire plaintext

    blocks = splitIntoBlocks(plainText, fileSignature.decode('utf-8'))

    cipherBlockSignature = fileSignature

    cipherText = ""

    for block in blocks:
        plainTextBlock = XOR(block.encode('utf-8'), cipherBlockSignature)

        cipherTextBlock = Ceaser.encrypt(plainTextBlock.decode('utf-8'), str(random.randint(0,25)))

        if cipherTextBlock == None:
            return

        cipherBlockSignature = sha256(cipherTextBlock.encode('utf-8')).hexdigest().encode('utf-8')

        cipherText += cipherTextBlock


    return cipherText

def decryptCaeser(cipherText: str, key: int, fileSignature):

    cipherTextBlocks = splitIntoBlocks(cipherText, fileSignature.decode('utf-8'))

    cipherBlockSignature = fileSignature
    decipheredPlainText =""

    random.seed(key)

    for block in cipherTextBlocks:
        decipheredBlock = Ceaser.decrypt(block,  str(random.randint(0,25)))

        if decipheredBlock == None:
            return

        plainTextBlock = XOR(decipheredBlock.encode('utf-8'), cipherBlockSignature).decode('utf-8')

        cipherBlockSignature = sha256(block.encode('utf-8')).hexdigest().encode('utf-8')

        decipheredPlainText += plainTextBlock

    if b'\FF'.decode('utf-8') in decipheredPlainText:
        return decipheredPlainText.split(b'\FF'.decode('utf-8'))[0]
    else:
        if "0" in decipheredPlainText:
            return decipheredPlainText.split("0")[0]

def encryptColumnar(plainText: str, key: int):

    random.seed(key)

    columnSize = (key%32)

    fileSignature = sha256(plainText.encode('utf-8')).hexdigest().encode('utf-8')  # signature of entire plaintext

    blocks = splitIntoBlocks(plainText, fileSignature.decode('utf-8'))

    cipherBlockSignature = fileSignature

    cipherText = ""

    for block in blocks:
        plainTextBlock = XOR(block.encode('utf-8'), cipherBlockSignature)


        possibleColumns = random.sample(range(1,columnSize+1),columnSize)

        possibleColumnsStringList = [str(x) for x in possibleColumns]

        possibleColumnsString = ",".join(possibleColumnsStringList)

        cipherTextBlock = Columnar.encrypt(plainTextBlock.decode('utf-8'), possibleColumnsString)

        if cipherTextBlock == None:
            return

        cipherBlockSignature = sha256(cipherTextBlock.encode('utf-8')).hexdigest().encode('utf-8')

        cipherText += cipherTextBlock

    return cipherText

def decryptColumnar(cipherText: str, key: int, fileSignature):
    random.seed(key)

    columnSize = (key % 32)

    cipherTextBlocks = splitIntoBlocks(cipherText, fileSignature.decode('utf-8'))

    #print(cipherTextBlocks)

    cipherBlockSignature = fileSignature
    decipheredPlainText =""

    random.seed(key)

    for block in cipherTextBlocks:

        possibleColumns = random.sample(range(1,columnSize+1),columnSize)

        possibleColumnsStringList = [str(x) for x in possibleColumns]

        possibleColumnsString = ",".join(possibleColumnsStringList)

        decipheredBlock = Columnar.decrypt(block,  possibleColumnsString)

        if decipheredBlock == None:
            return

        plainTextBlock = XOR(decipheredBlock.encode('utf-8'), cipherBlockSignature).decode('utf-8')

        cipherBlockSignature = sha256(block.encode('utf-8')).hexdigest().encode('utf-8')

        decipheredPlainText += plainTextBlock

    if b'\FF'.decode('utf-8') in decipheredPlainText:
        return decipheredPlainText.split(b'\FF'.decode('utf-8'))[0]
    else:
        if "0" in decipheredPlainText:
            return decipheredPlainText.split("0")[0]
        else:
            return decipheredPlainText

def splitIntoBlocks(text: str, signature: str):  # of 256 bits
    blocks = []  #

    block = ""  # max size is 256 bits

    for character in text:
        block += character

        if len(block) == 32:
            blocks.append(block)
            block = ""

    if len(block) < 32 and len(block) != 0:
        i = 0
        while len(block) < 32:
            if 32 - len(block) > 3:
                block += bytes(b'\FF').decode('utf-8')
            else:
                #block += signature[i]
                block += "0"
                i += 1

        blocks.append(block)

    return blocks


def XOR(operand1: bytes, operand2: bytes):
    return bytes(a ^ b for a, b in zip(operand1, operand2))


# https://www.reddit.com/r/learnpython/comments/zz76oc/how_would_i_xor_2_bytes_objects/



#plainText = "In this tutorial, we are going to learn how to implement Some"

# with open('largetext.txt','r') as f:
#       plainText = f.read()
#
# print(len(plainText))
#
# fileSignature = sha256(plainText.encode('utf-8')).hexdigest().encode('utf-8')
#
# #print(plainText)
#
#
# #cipherText = encryptCaeser(plainText, 5)
# key = 12312
# cipherText = encryptColumnar(plainText, key)
#
# #print(cipherText)
#
# #decipheredPlainText = decryptCaeser(cipherText,key,fileSignature)
# decipheredPlainText = decryptColumnar(cipherText,key,fileSignature)
#
#
# #print(decipheredPlainText)
#
# testHash = sha256(decipheredPlainText.encode('utf-8')).hexdigest().encode('utf-8')
#
# if testHash == fileSignature:
#     print("Encrypting and Decrypting processes are successful")
# else:
#     print("FAILED!")
