import os
import secrets
import hashlib
from tinyec import registry
from Crypto.Cipher import AES
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

curve = registry.get_curve('brainpoolP256r1')

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def process_files(input_folder, output_folder, pubKey):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for filename in os.listdir(input_folder):
        if filename.endswith(".txt"):
            input_path = os.path.join(input_folder, filename)
            output_path = os.path.join(output_folder, f"encrypted_{filename}")

            with open(input_path, 'rb') as file:
                msg = file.read()

            encrypted = encrypt_ECC(msg, pubKey)
            (ciphertext, nonce, authTag, ciphertextPubKey) = encrypted

            with open(output_path, 'wb') as file:
                file.write(ciphertext + nonce + authTag + ciphertextPubKey.x.to_bytes(32, 'big') + ciphertextPubKey.y.to_bytes(32, 'big'))

            print(Fore.GREEN + f"Encrypted {filename} and saved as {output_path}")

def get_folders():
    return [f for f in os.listdir('.') if os.path.isdir(f)]

def select_folder(folders):
    print(Fore.CYAN + "\nAvailable folders:")
    for i, folder in enumerate(folders, 1):
        print(f"{i}. {folder}")
    while True:
        try:
            choice = int(input(Fore.YELLOW + "\nSelect a folder number: "))
            if 1 <= choice <= len(folders):
                return folders[choice - 1]
            else:
                print(Fore.RED + "Invalid choice. Please try again.")
        except ValueError:
            print(Fore.RED + "Please enter a number.")

def get_encryption_key():
    while True:
        key = input(Fore.YELLOW + "\nEnter encryption key (at least 8 characters): ")
        if len(key) >= 8:
            return key
        else:
            print(Fore.RED + "Key must be at least 8 characters long. Please try again.")

def main_menu():
    while True:
        print(Fore.CYAN + "\n" + "=" * 40)
        print(Fore.CYAN + "ECC Encryption Tool")
        print(Fore.CYAN + "=" * 40)
        print(Fore.WHITE + "1. Encrypt files")
        print(Fore.WHITE + "2. Exit")
        
        choice = input(Fore.YELLOW + "\nEnter your choice (1-2): ")
        
        if choice == '1':
            folders = get_folders()
            input_folder = select_folder(folders)
            
            encryption_key = get_encryption_key()
            privKey = int.from_bytes(hashlib.sha256(encryption_key.encode()).digest(), 'big')
            pubKey = privKey * curve.g
            
            output_folder = input(Fore.YELLOW + "\nEnter name for output folder: ")
            
            process_files(input_folder, output_folder, pubKey)
        elif choice == '2':
            print(Fore.GREEN + "Thank you for using the ECC Encryption Tool. Goodbye!")
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()

print("Script execution completed. Press Enter to exit.")
input()