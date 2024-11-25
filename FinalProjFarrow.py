import os
from cryptography.fernet import Fernet

# Generates a Key and saves it to a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    return key

# Reads the key file
def load_key():
    return open("secret.key", "rb").read()

# Function to verify the user's key input
def verify_key(user_input_key):
    try:
        # Try loading the key from file
        correct_key = load_key()
        # Check if the user input key matches the correct key
        if user_input_key == correct_key:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error loading the key: {e}")
        return False

# Encrypts one file
def encrypt_file(file_path, key):
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Creates Fernet object with key
    fernet = Fernet(key)

    # Encrypt the data of file
    encrypted_data = fernet.encrypt(file_data)

    # Save the encrypted data to a new file with the .enc extension
    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    print(f"Encrypted {file_path} -> {encrypted_file_path}")

    # Delete the original unencrypted file
    os.remove(file_path)
    print(f"Original file {file_path} deleted.")

# Function to decrypt a single file
def decrypt_file(file_path, key):
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    # Create a Fernet object with the provided key
    fernet = Fernet(key)

    # Decrypt the data
    decrypted_data = fernet.decrypt(encrypted_data)

    # Save the decrypted data to a new file (removing the .enc extension)
    decrypted_file_path = file_path[:-4]  # Remove the .enc extension
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"Decrypted {file_path} -> {decrypted_file_path}")

    # Deletes encrypted file
    os.remove(file_path)
    print(f"Encrypted file {file_path} deleted.")

# Encrypts all files in a given directory
def encrypt_files_in_folder(folder_path):
    # Check if key file exists, if not generate a new one
    if not os.path.exists("secret.key"):
        print("Generating encryption key...")
        key = generate_key()
    else:
        key = load_key()

    # Loop through all files in the specified folder
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)

        # Skip directories and only encrypt files
        if os.path.isfile(file_path):
            encrypt_file(file_path, key)

# Function to decrypt all encrypted files in a given directory
def decrypt_files_in_folder(folder_path):
    # Ask the user for the decryption key
    user_input_key = input("Enter the decryption key: ").encode()

    # Check the key
    if not verify_key(user_input_key):
        print("This is incorrect! Decryption canceled.")
        return

    print("Key verified. Continuing Decryption")

    # If the key is correct, proceed with decryption
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)

        # Only decrypt files with the .enc extension
        if os.path.isfile(file_path) and file_path.endswith(".enc"):
            decrypt_file(file_path, user_input_key)

# Main function to handle user input and action choice
def main():
    action = input("Do you want to encrypt or decrypt files? (encrypt/decrypt): ").strip().lower()
    
    if action not in ["encrypt", "decrypt"]:
        print("Invalid! Choose 'encrypt' or 'decrypt'.")
        return

    folder_path = input("Enter the folder path: ").strip()

    if action == "encrypt":
        encrypt_files_in_folder(folder_path)
        print("Encryption complete.")

    elif action == "decrypt":
        decrypt_files_in_folder(folder_path)
        print("Decryption complete.")

# Main execution
if __name__ == "__main__":
    main()
