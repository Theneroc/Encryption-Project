import math


def validateKey(key:str):

    if not key.isnumeric():
        return False
    for i in range(len(key)):  # check for negative numbers or 0 in the key
        if int(key[i]) <= 0:
            return False

    for i in range(len(key)):  # check if there are out of bounds numbers in the key
        flag = False
        for j in range(1, len(key) + 1):
            if key[i] == str(j):
                flag = True
                break
        if not flag:
            return False

    for i in range(len(key)):  # check if there are repititions of values in the key
        for j in range(i + 1, len(key)):
            if key[i] == key[j]:
                return False  # invalid

    return True  # Valid


def encrypt(key:str, plainText):
    if (not validateKey(key)):
        return
    table = []

    for i in range(int(math.ceil(len(plainText) / len(key)))):
        table.append([])
        for j in range(len(key)):
            table[i].append([])

    columnIndex = 0
    rowIndex = 0
    for letter in plainText:

        table[rowIndex][columnIndex] = letter

        columnIndex += 1
        if columnIndex == len(key):
            columnIndex = 0
            rowIndex += 1

    for i in range(len(table)):
        for j in range(len(table[i])):
            if len(table[i][j]) == 0:
                table[i][j] = '_'


    keyList = []

    for i in range(len(key)):
        keyList.append(int(key[i]) - 1)

    cipherText = ""
    for i in keyList:
        for j in range(len(table)):
            if len(table[j][i]) == 0:
                continue
            else:
                cipherText += table[j][i]


    return cipherText


def decrypt(key:str,cipherText):
    if not validateKey(key):
        return
    table = []

    columnLength = int(math.ceil(len(cipherText) / len(key)))

    for i in range(columnLength):
        table.append([])
        for j in range(len(key)):
            table[i].append([])

    keyList = []

    for i in range(len(key)):
        keyList.append(int(key[i]) - 1)

    columnIndex = 0
    rowIndex = 0

    for letter in cipherText:

        table[rowIndex][keyList[columnIndex]] = letter

        rowIndex += 1

        if rowIndex == columnLength:
            rowIndex = 0
            columnIndex += 1

    plainText = ""
    for i in range(len(table)):
        for j in range(len(table[i])):
            if len(table[i][j]) == 0:
                continue
            else:
                plainText += table[i][j]
    return  plainText
