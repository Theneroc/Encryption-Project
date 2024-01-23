import math
import random


def encrypt(plainText, seed: int):
    random.seed(seed)

    keyLen = (seed%10)

    if keyLen<4:
        keyLen=3

    firstKey = random.sample(range(0, keyLen), keyLen)
    #print(firstKey)

    table = []
    newTable = []

    #print(firstKey)
    k = 0
    for i in range(int(math.ceil(len(plainText) / len(firstKey)))):  # number of rows
        table.append([])
        newTable.append([])
        for j in range(len(firstKey)):  # number of columns
            if k < len(plainText):
                table[i].append(plainText[k])
                k += 1
            else:
                table[i].append("$")
            newTable[i].append("$")

    #(table)
    #print(newTable)
    columnIndex = 0
    rowIndex = 0

    for i in firstKey:
        for j in range(len(table)):
            newTable[rowIndex][columnIndex] = table[j][i]
            rowIndex += 1
        rowIndex = 0
        columnIndex += 1

    #print(newTable)

    secondKeyList = random.sample(range(0, len(table)), len(table))
    #print(secondKeyList)

    cipherText = ""

    for i in secondKeyList:
        for j in range(len(table[i])):
            if newTable[i][j]:
                cipherText += newTable[i][j]
            else:
                cipherText += "$"

    #print(cipherText)

    return cipherText


def decrypt(cipherText, seed: int):

    keyLen = (seed%10)
    if keyLen<4:
        keyLen=3

    random.seed(seed)

    firstKey = random.sample(range(0, keyLen), keyLen)
    #print(firstKey)

    rows = int(math.ceil(len(cipherText) / len(firstKey)))

    secondKey = random.sample(range(0, rows), rows)
    #print(secondKey)

    newTable = []
    for row in range(rows):
        newTable.append([])
        for col in range(keyLen):
            newTable[row].append([])
    row = 0
    col = 0
    for letter in cipherText:
        newTable[secondKey[row]][firstKey[col]] = letter
        if col < keyLen - 1:
            col += 1
        else:
            col = 0
            row += 1

    #print(newTable)
    plainText = ""
    for i in range(rows):
        for j in range(keyLen):
            if newTable[i][j] != "$" and not len(newTable[i][j])==0:
                print(newTable)
                #print(keyLen)
                #print(newTable[i][j])
                plainText += newTable[i][j]
    #print(plainText)
    return plainText


#cipherText = encrypt("My name is Izzat and I like to goon 24/7 with khalil and othman", 52)
#print(decrypt(cipherText, 52))
