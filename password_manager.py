# Import Statements
import os
import hashlib
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hmac, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from getpass import getpass

# Constants
SALT_SIZE = 16  # 16 bytes for salt
NONCE_SIZE = 16  # 16 bytes for AES-CTR nonce
BLOCK_SIZE = 16  # AES block size

#hash and salt the master password
def hash_master_password(master_password):
    salt = os.urandom(SALT_SIZE)
    hash_object = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    return salt, hash_object

# validate the master password against the stored hash
def validate_master_password(input_password, stored_salt, stored_hash):
    hash_object = hashlib.pbkdf2_hmac('sha256', input_password.encode(), stored_salt, 100000)
    return hash_object == stored_hash

# backup the master key using RSA encryption
def backup_master_key(master_key):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("rsa_private.pem", "wb") as priv_file:
        priv_file.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))

    with open("rsa_public.pem", "wb") as pub_file:
        pub_file.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    encrypted_master_key = public_key.encrypt(
        master_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open("backup_key.txt", "wb") as file:
        file.write(encrypted_master_key)

# Function to recover the master key using the RSA private key
def recover_master_key():
    with open("rsa_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open("backup_key.txt", "rb") as file:
        encrypted_master_key = file.read()

    master_key = private_key.decrypt(
        encrypted_master_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return master_key

# Function to load or generate encryption keys
def load_encryption_key(master_password):
    salt, stored_hash = read_master_password()
    if validate_master_password(master_password, salt, stored_hash):
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        key = kdf.derive(master_password.encode())
        return key[:16], key[16:]
    else:
        raise ValueError("Invalid master password")

# encrypt the service name using AES-ECB
def encrypt_servicename(service_name, encryption_key):
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(service_name.encode()) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

# decrypt the service name using AES-ECB
def decrypt_servicename(encrypted_service_name, encryption_key):
    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = decryptor.update(encrypted_service_name) + decryptor.finalize()
    return unpadder.update(decrypted_data) + unpadder.finalize()

# encrypt the password
def encrypt_password(password, encryption_key):
    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()
    return encrypted_password, nonce

# decrypt the password using AES-CTR
def decrypt_password(encrypted_password, nonce, encryption_key):
    cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_password) + decryptor.finalize()).decode()

# add HMAC for integrity check
def add_hmac(encrypted_service_name, encrypted_password, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_service_name + encrypted_password)
    return h.finalize()

# verify the integrity using the HMAC
def verify_hmac(encrypted_service_name, encrypted_password, key, hmac_value):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_service_name + encrypted_password)
    try:
        h.verify(hmac_value)
        return True
    except Exception:
        return False

# Function to add a new service, username and password
def add_service(service_name, username, password, encryption_key, hmac_key):
    encrypted_service_name = encrypt_servicename(service_name, encryption_key)
    encrypted_password, nonce = encrypt_password(password, encryption_key)
    integrity_hmac = add_hmac(encrypted_service_name, encrypted_password, hmac_key)

    entry = {
        "service_name": encrypted_service_name.hex(),
        "username": username,
        "password": encrypted_password.hex(),
        "nonce": nonce.hex(),
        "hmac": integrity_hmac.hex()
    }

    # Append the entry to master.txt
    with open("master.txt", "a") as file:
        file.write(json.dumps(entry) + "\n")


# Function to retrieve a password
def retrieve_service(service_name, encryption_key, hmac_key):
    encrypted_service_name = encrypt_servicename(service_name, encryption_key)  # Encrypt using AES-ECB

    with open("master.txt", "r") as file:
        entries = [json.loads(line.strip()) for line in file.readlines()]

    for entry in entries:
        stored_service_name = bytes.fromhex(entry["service_name"])
        stored_password = bytes.fromhex(entry["password"])
        nonce = bytes.fromhex(entry["nonce"])
        stored_hmac = bytes.fromhex(entry["hmac"])

        if stored_service_name == encrypted_service_name:
            if verify_hmac(stored_service_name, stored_password, hmac_key, stored_hmac):
                return decrypt_password(stored_password, nonce, encryption_key)
    return "Service not found or data integrity compromised!"


 
# Function to read the master password hash and salt from the file
def read_master_password():
    with open("master_pass.txt", "rb") as f:
        data = f.read()
        return data[:SALT_SIZE], data[SALT_SIZE:]

# Function for the signup process to set a new master password
def signup():
    master_password = getpass("Create a master password: ")
    salt, hashed_password = hash_master_password(master_password)
    with open("master_pass.txt", "wb") as f:
        f.write(salt + hashed_password)
    print("Master password set successfully.")
    backup_master_key(hashed_password)
    main()  # Re-run main to let user enter the password again after signup

# Function to update the password for an existing service
def update_service(service_name, new_password, encryption_key, hmac_key):
    encrypted_service_name = encrypt_servicename(service_name, encryption_key)
    with open("master.txt", "r") as file:
        entries = [json.loads(line.strip()) for line in file.readlines()]
    
    updated = False
    for entry in entries:
        stored_service_name = bytes.fromhex(entry["service_name"])
        if stored_service_name == encrypted_service_name:
            encrypted_password, nonce = encrypt_password(new_password, encryption_key)
            entry["password"] = encrypted_password.hex()
            entry["nonce"] = nonce.hex()
            entry["hmac"] = add_hmac(stored_service_name, encrypted_password, hmac_key).hex()
            updated = True
            break
    
    if updated:
        with open("master.txt", "w") as file:
            for entry in entries:
                file.write(json.dumps(entry) + "\n")
        print(f"Password for '{service_name}' updated successfully.")
    else:
        print(f"Service '{service_name}' not found.")

# Function to delete an existing service
def delete_service(service_name, encryption_key):
    encrypted_service_name = encrypt_servicename(service_name, encryption_key)
    with open("master.txt", "r") as file:
        entries = [json.loads(line.strip()) for line in file.readlines()]
    
    entries = [entry for entry in entries if bytes.fromhex(entry["service_name"]) != encrypted_service_name]
    
    with open("master.txt", "w") as file:
        for entry in entries:
            file.write(json.dumps(entry) + "\n")
    
    print(f"Service '{service_name}' deleted successfully.")

# Function to change the master password
def change_master_password(old_password):
    try:
        # Read the stored salt and hash from master_pass.txt
        salt, stored_hash = read_master_password()

        # Validate the current master password
        if not validate_master_password(old_password, salt, stored_hash):
            print("Invalid current master password. Please try again.")
            return
        
        print("Current master password validated.")

        # Prompt for a new master password
        new_password = getpass("Enter new master password: ")
        confirm_password = getpass("Confirm new master password: ")

        # Ensure the new passwords match
        if new_password != confirm_password:
            print("New passwords do not match. Please try again.")
            return

        # Generate a new salt and hash for the new password
        new_salt, new_hashed_password = hash_master_password(new_password)


        # Update master_pass.txt with the new salt and hashed password
        with open("master_pass.txt", "wb") as f:
            f.write(new_salt + new_hashed_password)
        
        print("Master password updated in master_pass.txt.")

        # Re-encrypt the backup master key with the new password
        backup_master_key(new_hashed_password)

        print("Backup key re-encrypted with the new master password.")

        # Notify the user of success
        print("Master password changed successfully.")
    except Exception as e:
        print(f"Error changing master password: {e}")

def recover_master_password():
    try:
        # Ask for the RSA private key file location
        private_key_file = input("Enter the RSA private key file location (default: rsa_private.pem): ") or "rsa_private.pem"
        if not os.path.exists(private_key_file):
            print(f"Private key file '{private_key_file}' not found.")
            return
        
        # Load the RSA private key
        with open(private_key_file, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        
        # Load the encrypted master key
        if not os.path.exists("backup_key.txt"):
            print("Backup key file not found. Recovery not possible.")
            return
        
        with open("backup_key.txt", "rb") as file:
            encrypted_master_key = file.read()
        
        # Decrypt the master key
        master_key = private_key.decrypt(
            encrypted_master_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print("Recovery successful!")
        print(f"Your master key (hashed password): {master_key.hex()}")
        
        # Option to reset the master password
        reset_choice = input("Would you like to reset your master password? (yes/no): ").strip().lower()
        if reset_choice in ["yes", "y"]:
            new_password = getpass("Enter new master password: ")
            confirm_password = getpass("Confirm new master password: ")
            
            if new_password != confirm_password:
                print("Passwords do not match. Reset aborted.")
                return
            
            # Generate new salt and hashed password
            new_salt, new_hashed_password = hash_master_password(new_password)
            
            # Write the new hashed password and salt to master_pass.txt
            with open("master_pass.txt", "wb") as f:
                f.write(new_salt + new_hashed_password)
            
            # Re-encrypt the master key with the new password
            new_encryption_key, _ = load_encryption_key(new_password)
            backup_master_key(new_hashed_password)
            
            print("Master password reset successfully.")
        else:
            print("Password reset skipped.")
    except Exception as e:
        print(f"Error during recovery: {e}")
#main
def main():
    if os.path.exists("master_pass.txt"):
        while True:
            print("\nPassword Manager Options:")
            print("1. Open Password Manager")
            print("2. Recover Master Password")
            print("3. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                while True:
                    master_password = getpass("Enter master password: ")
                    salt, stored_hash = read_master_password()

                    if validate_master_password(master_password, salt, stored_hash):
                        encryption_key, hmac_key = load_encryption_key(master_password)
                        print("Master password validated!")
                        
                        while True:
                            print("\nPassword Manager Options:")
                            print("1. Add New Service")
                            print("2. Retrieve Password")
                            print("3. Update Password")
                            print("4. Delete Service")
                            print("5. Change Master Password")
                            print("6. Exit")
                            sub_choice = input("Enter your choice: ")

                            if sub_choice == "1":
                                service_name = input("Enter the service name: ")
                                username = input("Enter the username: ")
                                password = getpass("Enter the password: ")
                                add_service(service_name, username, password, encryption_key, hmac_key)
                                print(f"Service '{service_name}' added successfully!")

                            elif sub_choice == "2":
                                service_name = input("Enter the service name: ")
                                password = retrieve_service(service_name, encryption_key, hmac_key)
                                print(f"Password for '{service_name}': {password}")

                            elif sub_choice == "3":
                                service_name = input("Enter the service name: ")
                                new_password = getpass("Enter the new password: ")
                                update_service(service_name, new_password, encryption_key, hmac_key)

                            elif sub_choice == "4":
                                service_name = input("Enter the service name: ")
                                delete_service(service_name, encryption_key)

                            elif sub_choice == "5":
                                old_password = getpass("Enter current master password: ")
                                change_master_password(old_password)

                            elif sub_choice == "6":
                                print("Exiting the program. Goodbye!")
                                return

                            else:
                                print("Invalid choice. Please try again.")
                        break 
                    else:
                        print("Incorrect master password. Please try again.")
                        continue  
            elif choice == "2":
                recover_master_password()

            elif choice == "3":
                print("Exiting the program. Goodbye!")
                break

            else:
                print("Invalid choice. Please try again.")
    else:
        print("No master password found. Please sign up.")
        signup()

if __name__ == "__main__":
    main()