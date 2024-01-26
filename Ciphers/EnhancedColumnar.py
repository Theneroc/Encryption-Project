import math
import random


def encrypt(plainText, seed: int, keyLen: int):
    random.seed(seed)

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
                table[i].append([])
            newTable[i].append([])

    #print(table)
    #print(newTable)
    col = 0
    row = 0

    for i in firstKey:
        for j in range(len(table)):
            newTable[row][col] = table[j][i]
            row += 1
        row = 0
        col += 1

    #print(newTable)

    secondKeyList = random.sample(range(0, len(table)), len(table))
    #print(secondKeyList)

    cipherText = ""

    for i in secondKeyList:
        for j in range(len(table[i])):
            if newTable[i][j]:
                cipherText += newTable[i][j]

    #print(cipherText)

    return cipherText


def decrypt(cipherText, seed: int, keyLen: int):
    random.seed(seed)

    firstKey = random.sample(range(0, keyLen), keyLen)
    #print(firstKey)

    rows = int(math.ceil(len(cipherText) / len(firstKey)))  # how many rows there are in the table, depending
    # on the size of cipherText and firstKey

    emptyCells = int(math.fabs(len(cipherText) - (keyLen * rows)))  # The amount of empty cells there are in the table
    #print("empty cells: ", emptyCells)
    secondKey = random.sample(range(0, rows), rows)
    #print(secondKey)

    table = []
    for row in range(rows):
        table.append([])
        for col in range(keyLen):
            table[row].append([])

    k = 0
    for row in secondKey:
        for col in firstKey:
            if row < rows - 1 or not (row == rows - 1 and col >= (keyLen - emptyCells)):
                if k < len(cipherText):
                    table[row][col] = cipherText[k]
                    k += 1

    #print(table)
    plainText = ""
    for i in range(rows):
        for j in range(len(table[i])):
            if table[i][j]:
                plainText += table[i][j]
    #print(plainText)
    return plainText
