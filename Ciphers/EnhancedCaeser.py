import random


def caesarDecipher(encrypted_message, shifts):
    result = ""
    for char, shift in zip(encrypted_message, shifts):
        if char.isalpha():
            is_upper = char.isupper()# uses the seed to shift back into the original character
            shifted_char = chr((ord(char) - ord('A' if is_upper else 'a') - shift) % 26 + ord('A' if is_upper else 'a'))
            result += shifted_char
        else:
            result += char

    return result


def caesarCipher(message, shifts):
    result = ""
    for char, shift in zip(message, shifts):
        if char.isalpha():
            is_upper = char.isupper()# uses the random seed index to shift the character
            shifted_char = chr((ord(char) - ord('A' if is_upper else 'a') + shift) % 26 + ord('A' if is_upper else 'a'))
            result += shifted_char
        else:
            result += char

    return result


def main():
    try:
        shiftNumber = int(input("Enter the No. of Shifts => "))

        random.seed(shiftNumber)
        # creating a seed based on the users input for the key
        # shiftNumber = 3
        # use this if you want to harcode it
    except ValueError:
        print("Enter Integer Value.")
        return
    message = input("Enter the plain-text you want to Encrypt => ")
    shifts = [random.randint(0, 25) for _ in message]
    print(shifts)

    encrypted = caesarCipher(message, shifts)
    print(f"Encrypted => {encrypted}")

    decrypted = caesarDecipher(encrypted, shifts)
    print(f"Decrypted => {decrypted}")


if __name__ == "__main__":
    main()
