
def validate(key:str):

    if not key.isnumeric():
        return False

    if int(key)>26 or int(key)<0:
        return False

    return True

def decrypt(message, key:str):
    result = ""

    if not validate(key):
        return
    else:
        key = int (key)

    for char in message:
        if char.isalpha():
            is_upper = char.isupper()  # checking because it could have diff ASCII values
            shifted_char = chr((ord(char) - ord('A' if is_upper else 'a') - key) % 26 + ord('A' if is_upper else 'a'))
            result += shifted_char
        else:
            result += char  # keeps the non-alphabet characters as they are
    return result

def encrypt(message, key:str):
    result = ""

    if not validate(key):
        return
    else:
        key = int (key)

    for char in message:
        if char.isalpha():
            is_upper = char.isupper()  # checking because it could have diff ASCII values
            shifted_char = chr((ord(char) - ord('A' if is_upper else 'a') + key) % 26 + ord('A' if is_upper else 'a'))
            result += shifted_char
        else:
            result += char  # keeps the non-alphabet characters as they are
    return result
