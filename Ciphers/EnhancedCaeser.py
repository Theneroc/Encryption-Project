import random


def decrypt(encrypted_message, seed):
    random.seed(seed)

    shifts = [random.randint(-25, 25) for _ in encrypted_message]

    result = ""
    for char, shift in zip(encrypted_message, shifts):
        if char.isalpha():
            is_upper = char.isupper()# uses the seed to shift back into the original character
            shifted_char = chr((ord(char) - ord('A' if is_upper else 'a') - shift) % 26 + ord('A' if is_upper else 'a'))
            result += shifted_char
        else:
            result += char

    return result


def encrypt(message, seed):
    random.seed(seed)
    shifts = [random.randint(-25, 25) for _ in message]
    result = ""
    for char, shift in zip(message, shifts):
        if char.isalpha():
            is_upper = char.isupper()# uses the random seed index to shift the character
            shifted_char = chr((ord(char) - ord('A' if is_upper else 'a') + shift) % 26 + ord('A' if is_upper else 'a'))
            result += shifted_char
        else:
            result += char

    return result


# key =12321
#
# plainText = "Khalil loves to goon to his own voice"
#
# print(plainText)
#
# cipherText = encrypt(plainText,key)
#
# print(cipherText)
#
# decipheredText = decrypt(cipherText,key)
#
# print(decipheredText)
