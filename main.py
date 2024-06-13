import sys
from colorama import init, Fore

# Initialise colorama
init()


# Function to Encrypt using the Vigenère cipher.
def vigenere_encrypt(plain_text, key):
    encrypted_text = ''

    # Repeat the key to match the length of the plaintext.
    key_repeated = (key * (len(plain_text) // len(key))) + key[:len(plain_text) % len(key)]

    # Iterate through each character in the plaintext.
    for i in range(len(plain_text)):
        if plain_text[i].isalpha():
            # Calculate the shift based on the corresponding key letter.
            shift = ord(key_repeated[i].upper()) - ord('A')

            # Encrypt uppercase and lowercase letters separately.
            if plain_text[i].isupper():
                encrypted_text += chr((ord(plain_text[i]) + shift - ord('A')) % 26 + ord('A'))
            else:
                encrypted_text += chr((ord(plain_text[i]) + shift - ord('a')) % 26 + ord('a'))
        else:
            encrypted_text += plain_text[i]

    return encrypted_text


# Decryption function for the Vigenère cipher
def vigenere_decrypt(cipher_text, key):
    decrypted_text = ''

    # Repeat the key to match the length of the ciphertext
    key_repeated = (key * (len(cipher_text) // len(key))) + key[:len(cipher_text) % len(key)]

    # Iterate through each character in the ciphertext
    for i in range(len(cipher_text)):
        if cipher_text[i].isalpha():
            # Calculate the shift based on the corresponding key letter
            shift = ord(key_repeated[i].upper()) - ord('A')

            # Decrypt uppercase and lowercase letters separately
            if cipher_text[i].isupper():
                decrypted_text += chr((ord(cipher_text[i]) - shift - ord('A')) % 26 + ord('A'))
            else:
                decrypted_text += chr((ord(cipher_text[i]) - shift - ord('a')) % 26 + ord('a'))
        else:
            decrypted_text += cipher_text[i]

    return decrypted_text



key = "KEY"
while True:
    # Get user input (Message to encrypt).
    plaintext = input('[!] Enter your message: ')

    # Encrypt the plaintext using the Vigenère cipher
    cipher_text = vigenere_encrypt(plaintext, key)

    # Print the results
    print(f"[+] Plaintext: {plaintext}")
    print(f"{Fore.GREEN}[+] Ciphertext: {cipher_text}")
    print(f"{Fore.RESET}", end='')

    ask_to_decrypt = input('\n[?] Do you want to decrypt the message?\n[?] Y or N: ').lower()

    if ask_to_decrypt == 'y':
        # Decrypt the ciphertext back to the original plaintext.
        decrypted_text = vigenere_decrypt(cipher_text, key)
        print(f"{Fore.GREEN}[+] Decrypted text: {decrypted_text}")
        print(f"{Fore.RESET}", end='')

    elif ask_to_decrypt == 'n':
        sys.exit()
    # When an invalid input is entered.
    else:
        print(f"{Fore.RED}[-] Invalid input.")
    print(f"{Fore.RESET}", end='')
