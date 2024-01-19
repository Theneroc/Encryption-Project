import math

#key input syntax must be 1,2,3,4....

def validateKey(key: str):

    keyAsString = "".join(key.split(","))
    if not keyAsString.isnumeric():
        return False

    key = key.split(',')

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


def encrypt(plainText, key: str):
    if (not validateKey(key)):
        return

    key = key.split(',')
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

    # for i in range(len(table)):
    #     for j in range(len(table[i])):
    #         if len(table[i][j]) == 0:
    #             table[i][j] = '_'

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

    #print(table)
    return cipherText


def decrypt(cipherText, key: str):
    if not validateKey(key):
        return

    key = key.split(',')

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

    rowLength = len(cipherText) // len(key)+1

    #print(rowLength)

    #print(len(cipherText))

    emptyCells =  int(math.fabs(len(cipherText) - (len(key) * rowLength)))

    # print("Empty Cells: "+str(emptyCells))
    # print("Len of key: "+str(len(key)))

    for letter in cipherText:

        # print(table)
        # print("The column Index: "+str(columnIndex))
        # print("The row: "+str(rowIndex))
        # print("The actual column: "+str(keyList[columnIndex]))
        # print((len(key) - emptyCells))
        # print((rowIndex == (rowLength-1) and keyList[columnIndex] >= (len(key) - emptyCells)))
        table[rowIndex][keyList[columnIndex]] = letter
        rowIndex += 1


        if (rowIndex == columnLength) or (rowIndex == (rowLength-1) and keyList[columnIndex] >= (len(key) - emptyCells)) :
            rowIndex = 0
            columnIndex += 1



    #print(table)

    plainText = ""
    for i in range(len(table)):
        for j in range(len(table[i])):
            if len(table[i][j]) == 0:
                continue
            else:
                plainText += table[i][j]
    return plainText


#cipherText = encrypt("I love shwarma it is the best", "52314")
#print(cipherText)

#print(decrypt(cipherText, "52314"))
#print(decrypt(encrypt("I love shwarma it is the best!!","7,4,6,2,3,5,1"),"7,4,6,2,3,5,1"))
