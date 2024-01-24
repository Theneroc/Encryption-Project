import random
from hashlib import sha256
from Ciphers import Ceaser, Columnar, EnhancedColumnar, EnhancedCaeser


# if an encryption or decryption method returns null, then the key is invalid.

def encryptCaeser(plainText: str, key: int):
    random.seed(key)

    fileSignature = sha256(plainText.encode('utf-8')).hexdigest().encode('utf-8')  # signature of entire plaintext

    blocks = splitIntoBlocks(plainText, fileSignature.decode('utf-8'))

    cipherBlockSignature = fileSignature

    cipherText = ""

    for block in blocks:
        plainTextBlock = XOR(block.encode('utf-8'), cipherBlockSignature)

        cipherTextBlock = Ceaser.encrypt(plainTextBlock.decode('utf-8'), str(random.randint(0, 25)))

        if cipherTextBlock == None:
            return

        cipherBlockSignature = sha256(cipherTextBlock.encode('utf-8')).hexdigest().encode('utf-8')

        cipherText += cipherTextBlock

    return cipherText


def decryptCaeser(cipherText: str, key: int, fileSignature):
    cipherTextBlocks = splitIntoBlocks(cipherText, fileSignature.decode('utf-8'))

    cipherBlockSignature = fileSignature
    decipheredPlainText = ""

    random.seed(key)

    for block in cipherTextBlocks:
        decipheredBlock = Ceaser.decrypt(block, str(random.randint(0, 25)))

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


def encryptEnhancedCaeser(plainText: str, key: int):
    random.seed(key)

    fileSignature = sha256(plainText.encode('utf-8')).hexdigest().encode('utf-8')  # signature of entire plaintext

    blocks = splitIntoBlocks(plainText, fileSignature.decode('utf-8'))

    cipherBlockSignature = fileSignature

    cipherText = ""

    for block in blocks:
        plainTextBlock = XOR(block.encode('utf-8'), cipherBlockSignature)

        currentKey = random.randint(0,
                                    999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999)

        cipherTextBlock = EnhancedCaeser.encrypt(plainTextBlock.decode('utf-8'), currentKey)

        if cipherTextBlock == None:
            return

        cipherBlockSignature = sha256(cipherTextBlock.encode('utf-8')).hexdigest().encode('utf-8')

        cipherText += cipherTextBlock

    return cipherText

def decryptEnhancedCaeser(cipherText: str, key: int, fileSignature):
    cipherTextBlocks = splitIntoBlocks(cipherText, fileSignature.decode('utf-8'))

    cipherBlockSignature = fileSignature
    decipheredPlainText = ""

    random.seed(key)

    for block in cipherTextBlocks:
        currentKey = random.randint(0,
                                    999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999)

        decipheredBlock = EnhancedCaeser.decrypt(block, currentKey)

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

    columnSize = (key % 32)

    fileSignature = sha256(plainText.encode('utf-8')).hexdigest().encode('utf-8')  # signature of entire plaintext

    blocks = splitIntoBlocks(plainText, fileSignature.decode('utf-8'))

    cipherBlockSignature = fileSignature

    cipherText = ""

    for block in blocks:
        plainTextBlock = XOR(block.encode('utf-8'), cipherBlockSignature)

        possibleColumns = random.sample(range(1, columnSize + 1), columnSize)

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

    # print(cipherTextBlocks)

    cipherBlockSignature = fileSignature
    decipheredPlainText = ""

    for block in cipherTextBlocks:

        possibleColumns = random.sample(range(1, columnSize + 1), columnSize)

        possibleColumnsStringList = [str(x) for x in possibleColumns]

        possibleColumnsString = ",".join(possibleColumnsStringList)

        decipheredBlock = Columnar.decrypt(block, possibleColumnsString)

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


def encryptEnhancedColumnar(plainText: str, key: int):
    random.seed(key)

    fileSignature = sha256(plainText.encode('utf-8')).hexdigest().encode('utf-8')  # signature of entire plaintext

    blocks = splitIntoBlocks(plainText, fileSignature.decode('utf-8'))
    cipherBlockSignature = fileSignature

    cipherText = ""

    for block in blocks:


        plainTextBlock = XOR(block.encode('utf-8'), cipherBlockSignature)

        currentKey = random.randint(0,
                                    999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999)

        cipherTextBlock = EnhancedColumnar.encrypt(plainTextBlock.decode('utf-8'), currentKey)

        if cipherTextBlock is None:
            return

        temp = cipherTextBlock
        print((temp.replace("$", "")))
        cipherBlockSignature = sha256(temp.replace("$", "").encode('utf-8')).hexdigest().encode('utf-8')

        cipherText += cipherTextBlock + (b'\\FE1234'.decode('utf-8'))

    return cipherText


def decryptEnchancedColumnar(cipherText: str, key: int, fileSignature):
    random.seed(key)

    cipherTextBlocks = cipherText.split(b'\\FE1234'.decode('utf-8'))

    cipherBlockSignature = fileSignature
    decipheredPlainText = ""
    print("\n")
    for block in cipherTextBlocks:

        if len(block) == 0:
            continue

        currentKey = random.randint(0,
                                    999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999)
        decipheredBlock = EnhancedColumnar.decrypt(block, currentKey)

        if decipheredBlock == None:
            return

        plainTextBlock = XOR(decipheredBlock.encode('utf-8'), cipherBlockSignature).decode('utf-8')

        print(decipheredBlock)

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
                # block += signature[i]
                block += "0"
                i += 1

        blocks.append(block)

    return blocks


def XOR(operand1: bytes, operand2: bytes):
    return bytes(a ^ b for a, b in zip(operand1, operand2))


# https://www.reddit.com/r/learnpython/comments/zz76oc/how_would_i_xor_2_bytes_objects/


# print(b'\\FE'.decode('utf-8'))

plainText = "In this tutorial, we are going to learn how to implement Some1234"

# with open('largetext.txt','r') as f:
#       plainText = f.read()

# print(len(plainText))
#
fileSignature = sha256(plainText.encode('utf-8')).hexdigest().encode('utf-8')
#
# #print(plainText)
#
#
# #cipherText = encryptCaeser(plainText, 5)
key = 12312
# cipherText = encryptColumnar(plainText, key)
#
cipherText = encryptEnhancedCaeser(plainText, key)
print(encryptCaeser(plainText,key))
print("\n")
print(cipherText)
#
# #decipheredPlainText = decryptCaeser(cipherText,key,fileSignature)
# decipheredPlainText = decryptColumnar(cipherText,key,fileSignature)

decipheredPlainText = decryptEnhancedCaeser(cipherText, key, fileSignature)
#
# print(decipheredPlainText)
#
testHash = sha256(decipheredPlainText.encode('utf-8')).hexdigest().encode('utf-8')
#
if testHash == fileSignature:
    print("Encrypting and Decrypting processes are successful")
else:
    print("FAILED!")
