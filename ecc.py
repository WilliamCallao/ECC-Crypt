import os
import secrets
import hashlib
import base64
from tinyec import registry
from tinyec.ec import Point
from Crypto.Cipher import AES
from colorama import init, Fore, Style
from tqdm import tqdm
from pick import pick

# Inicializar colorama
init(autoreset=True)

# Definir la curva elíptica
curve = registry.get_curve('brainpoolP256r1')

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

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

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

def encrypt_filename(filename, key):
    encrypted = base64.urlsafe_b64encode(hashlib.sha256(filename.encode() + key.encode()).digest()).decode()[:32]
    return encrypted + os.path.splitext(filename)[1]  # Mantener la extensión del archivo

def decrypt_filename(encrypted_filename, key):
    # Esta función es un placeholder. En la práctica, necesitarías una forma de mapear
    # los nombres encriptados a los originales, ya que la encriptación no es reversible.
    return "decrypted_" + encrypted_filename

def process_files(input_folder, output_folder, key, mode='encrypt'):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    files = [f for f in os.listdir(input_folder) if os.path.isfile(os.path.join(input_folder, f))]
    
    with tqdm(total=len(files), desc=f"{'Encrypting' if mode == 'encrypt' else 'Decrypting'} files", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt}") as pbar:
        for filename in files:
            input_path = os.path.join(input_folder, filename)
            
            try:
                if mode == 'encrypt':
                    encrypted_filename = encrypt_filename(filename, str(key.x) + str(key.y))
                    output_path = os.path.join(output_folder, encrypted_filename)
                    
                    with open(input_path, 'rb') as file:
                        msg = file.read()

                    encrypted = encrypt_ECC(msg, key)
                    (ciphertext, nonce, authTag, ciphertextPubKey) = encrypted

                    with open(output_path, 'wb') as file:
                        file.write(ciphertext + nonce + authTag + ciphertextPubKey.x.to_bytes(32, 'big') + ciphertextPubKey.y.to_bytes(32, 'big'))
                
                elif mode == 'decrypt':
                    with open(input_path, 'rb') as file:
                        encrypted_data = file.read()
                    
                    ciphertext = encrypted_data[:-96]
                    nonce = encrypted_data[-96:-80]
                    authTag = encrypted_data[-80:-64]
                    ciphertextPubKey_x = int.from_bytes(encrypted_data[-64:-32], 'big')
                    ciphertextPubKey_y = int.from_bytes(encrypted_data[-32:], 'big')
                    ciphertextPubKey = Point(curve, ciphertextPubKey_x, ciphertextPubKey_y)

                    encryptedMsg = (ciphertext, nonce, authTag, ciphertextPubKey)
                    decrypted_msg = decrypt_ECC(encryptedMsg, key)

                    decrypted_filename = decrypt_filename(filename, str(key))
                    output_path = os.path.join(output_folder, decrypted_filename)

                    with open(output_path, 'wb') as file:
                        file.write(decrypted_msg)

                pbar.update(1)
            except Exception as e:
                print(Fore.RED + f"Error processing file {filename}: {str(e)}")

    print(Fore.GREEN + f"{'Encryption' if mode == 'encrypt' else 'Decryption'} completed. Files saved in {output_folder}")

def get_folders():
    return [f for f in os.listdir('.') if os.path.isdir(f)]

def select_folder(folders):
    title = 'Please choose a folder (use arrow keys to move, Enter to select):'
    option, index = pick(folders, title)
    return option

def get_encryption_key():
    while True:
        key = input(Fore.YELLOW + "\nEnter encryption key (at least 8 characters): ")
        if len(key) >= 8:
            return key
        else:
            print(Fore.RED + "Key must be at least 8 characters long. Please try again.")

def main_menu():
    while True:
        title = 'ECC Encryption/Decryption Tool'
        options = ['Encrypt files', 'Decrypt files', 'Exit']
        option, index = pick(options, title)
        
        if index in [0, 1]:  # Encrypt or Decrypt
            folders = get_folders()
            input_folder = select_folder(folders)
            
            encryption_key = get_encryption_key()
            privKey = int.from_bytes(hashlib.sha256(encryption_key.encode()).digest(), 'big')
            pubKey = privKey * curve.g
            
            output_folder = input(Fore.YELLOW + "\nEnter name for output folder: ")
            
            if index == 0:
                process_files(input_folder, output_folder, pubKey, mode='encrypt')
            else:
                process_files(input_folder, output_folder, privKey, mode='decrypt')
        elif index == 2:  # Exit
            print(Fore.GREEN + "Thank you for using the ECC Encryption/Decryption Tool. Goodbye!")
            break

if __name__ == "__main__":
    main_menu()

print("Script execution completed. Press Enter to exit.")
input()