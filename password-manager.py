# Password Manager in python

import json, hashlib, getpass, os, pyperclip, sys, string, secrets
from cryptography.fernet import Fernet

# Generate new passwords
def random_password():

    # Password length
    print("")
    length = int(input("[*] Enter password length: "))
    x = True
    characterList = ""
    password = []

    #Options for generating password
    print("[*] Password Options")
    print("[*] 1. Letters")
    print("[*] 2. Digits")
    print("[*] 3. Special Characters")
    print("[*] 4. All options")
    print("[*] Type ur options all on same line.")

    while(x == True):
        choice = int(input("[*] Option(s): "))

        if('1' in str(choice)):
            # Adding letters to possible characters
            characterList += string.ascii_letters
            print("[+] Added letters to possible characters")
            x = False
        if('2' in str(choice)):
            
            # Adding digits to possible characters
            characterList += string.digits
            print("[+] Added digits to possible characters")
            x = False
        if('3' in str(choice)):
            
            # Adding special characters to possible characters
            characterList += string.punctuation
            print("[+] Added special characters to possible characters")
            x = False
        if('4' in str(choice)):
            
            # Adding special characters to possible characters
            characterList += string.punctuation
            characterList += string.ascii_letters
            characterList += string.digits
            print("[+] Added all characters to possible characters")
            x = False
        else:
            print("[-] ERROR: Please pick a valid option!")
    
    for i in range(length):
        password = ''
        for i in range(length):
            password += ''.join(secrets.choice(characterList))

    # printing password as a string
    print("[+] The random password is " + "".join(password))
    password_strength_checker(password)

    return password

# Password strength checker
def password_strength_checker(password):
    n = len(password)  

    # Checking lower alphabet in string  
    hasLower = False
    hasUpper = False
    hasDigit = False
    specialChar = False
    normalChars = "abcdefghijklmnopqrstu"
    "vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 "
    
    for i in range(n): 
        if password[i].islower(): 
            hasLower = True
        if password[i].isupper(): 
            hasUpper = True
        if password[i].isdigit(): 
            hasDigit = True
        if password[i] not in normalChars: 
            specialChar = True

    # Strength of password  
    print("[*] Password Strength: ", end = "") 
    if (hasLower and hasUpper and 
        hasDigit and specialChar and n >= 8): 
        print("Strong") 
        
    elif ((hasLower or hasUpper) and 
        specialChar and n >= 6): 
        print("Moderate") 
    else: 
        print("Weak") 

# Hashing the Master Password
def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()

# Generate a secret key. This should be done only once
def generate_key():
    return Fernet.generate_key()

# Initialize Fernet cipher with the provided key
def initialize_cipher(key):
    return Fernet(key)

# Encrypt a password
def encrypt_password(cipher, password):
    return cipher.encrypt(password.encode()).decode()

# Decrypt a password
def decrypt_password(cipher, encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# Function to register user
def register(username, master_password):
    # Encrypt the master password before storing it
    hashed_master_password = hash_password(master_password)
    user_data = {'username': username, 'master_password': hashed_master_password}
    file_name = 'user_data.json'

    if os.path.exists(file_name) and os.path.getsize(file_name) == 0:
        with open(file_name, 'w') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!!")
    else:
        with open(file_name, 'x') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!!")

# Log user in 
def login(username, entered_password):
    try:
        with open('user_data.json', 'r') as file:
            user_data = json.load(file)

        stored_password_hash = user_data.get('master_password')
        entered_password_hash = hash_password(entered_password)

        if entered_password_hash == stored_password_hash and username == user_data.get('username'):
            print("\n[+] Login Successful..\n")
        else:
            print("\n[-] Invalid Login credentials. Please use the credentials you used to register.\n")
            sys.exit()

    except Exception:
        print("\n[-] You have not registered. Please do that.\n")
        sys.exit()

# View saved websites
def view_websites():
    try:
        with open('passwords.json', 'r') as data:
            view = json.load(data)
            print("\n[*]Websites you saved...\n")
            for x in view:
                print(x['website'])
            print('\n')
    except FileNotFoundError:
        print("\n[-] You have not saved any passwords!\n")

# Load or generate the encryption key
key_filename = 'encryption_key.key'
if os.path.exists(key_filename):
    with open(key_filename, 'rb') as key_file:
        key = key_file.read()
else:
    key = generate_key()
    with open(key_filename, 'wb') as key_file:
        key_file.write(key)

cipher = initialize_cipher(key)

# Save password
def add_password(website, password):
    # Check if passwords.json exists
    if not os.path.exists('passwords.json'):
        # If passwords.json doesn't exist, initialize it with an empty list
        data = []
    else:
        # Load existing data from passwords.json
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            # Handle the case where passwords.json is empty or invalid JSON.
            data = []

    # Encrypt the password
    encrypted_password = encrypt_password(cipher, password)

    # Create a dictionary to store the website and password
    password_entry = {'website': website, 'password': encrypted_password}
    data.append(password_entry)

    # Save the updated list back to passwords.json
    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)

# Retrieve a saved password
def get_password(website):
    # Check if passwords.json exists
    if not os.path.exists('passwords.json'):
        return None

    # Load existing data from passwords.json
    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []
    # Loop through all the websites and check if the requested website exists.
    for entry in data:
        if entry['website'] == website:
            # Decrypt and return the password
            decrypted_password = decrypt_password(cipher, entry['password'])
            return decrypted_password

    return None

def main():
    # Print banner
    print(r" ____                                     _ ")
    print(r"|  _ \ __ _ ___ _____      _____  _ __ __| |")
    print(r"| |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` |")
    print(r"|  __/ (_| \__ \__ \\ V  V / (_) | | | (_| |")
    print(r"|_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|")
    print(r" __  __                                     ")
    print(r"|  \/  | __ _ _ __   __ _  __ _  ___ _ __   ")
    print(r"| |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|  ")
    print(r"| |  | | (_| | | | | (_| | (_| |  __/ |     ")
    print(r"|_|  |_|\__,_|_| |_|\__,_|\__, |\___|_|     ")
    print(r"                          |___/             ")

    # Infinite loop to keep the program running until the user chooses to quit
    while True:
        print("")
        print("-" * 45)
        print("")
        print("[*] 1. Register a new master password")
        print("[*] 2. Login to an existing account")
        print("[*] 3. Generate a random password")
        print("[*] 4. Test a passwords strength")
        print("[*] 5. Reset Database (keys and passwords)")
        print("[*] 6. Quit password manager")
        print("")
        
        choice = input("[*] Enter your choice: ")

        if choice == '1':  # If a user wants to register
            file = 'user_data.json'
            if os.path.exists(file) and os.path.getsize(file) != 0:
                print("\n[-] Master user already exists!!")
                sys.exit()
            else:
                username = input("[*] Enter your username: ")
                master_password = getpass.getpass("[*] Enter your master password: ")
                register(username, master_password)

        elif choice == '2':  # If a User wants to log in
            file = 'user_data.json'
            if os.path.exists(file):
                username = input("[*] Enter your username: ")
                master_password = getpass.getpass("[*] Enter your master password: ")
                login(username, master_password)
            else:
                print("\n[-] You have not registered. Please do that.\n")
                sys.exit()
            # Various options after a successful Login.
            while True:
                print("[*] 1. Add Password")
                print("[*] 2. Get Password")
                print("[*] 3. View Saved websites")
                print("[*] 4. Quit")

                password_choice = input("[*] Enter your choice: ")
                if password_choice == '1':  # If a user wants to add a password
                    website = input("[*] Enter website: ")
                    print("[*] Do you want to generate a secure password or choose your own.")
                    print("[*] 1. Generate new password automatically")
                    print("[*] 2. Choose your own")

                    x = True

                    while (x == True):

                        choice = input("[*] Choice: ")

                        if (choice == "1"):
                            password = random_password()
                            x = False

                        elif (choice == "2"):
                            password = getpass.getpass("[*] Enter password: ")
                            password_strength_checker(password)
                            x = False

                        else:
                            print("[-] ERROR: Please pick either 1 or 2")
                    
                    # Encrypt and add the password
                    add_password(website, password)
                    print("\n[+] Password added!\n")

                elif password_choice == '2':  # If a User wants to retrieve a password
                    website = input("[*] Enter website: ")
                    decrypted_password = get_password(website)
                    if website and decrypted_password:
                        # Copy password to clipboard for convenience
                        pyperclip.copy(decrypted_password)
                        print(f"\n[+] Password for {website}: {decrypted_password}\n[+] Password copied to clipboard.\n")
                    else:
                        print("\n[-] Password not found! Did you save the password?"
                            "\n[-] Use option 3 to see the websites you saved.\n")

                elif password_choice == '3':  # If a user wants to view saved websites
                    view_websites()

                elif password_choice == '4':  # If a user wants to quit the password manager
                    break

        elif choice == '3':  # If a user wants to generate a random password
            password = random_password()

        elif choice == '4':  # If a user wants to check the strength of a single password
            password = getpass.getpass("[*] Enter password: ")
            password_strength_checker(password)

        elif choice == '5':  # If a user wants to clean up
            print("[*] Are you sure?")
            print("[*] This will delete old password database, keys, and login info")
            confirm = input("[*] Confirm choice (y or n): ")

            x = False

            while x == False:
                if confirm == 'y':
                    print("[-] Deleting files...")

                    key_file = "encryption_key.key"
                    # If file exists, delete it.
                    if os.path.isfile(key_file):
                        os.remove(key_file)
                        print("[-] Removed %s" % key_file)
                    else:
                        # If it fails, inform the user.
                        print("[-] Error: %s file not found" % key_file)

                    password_file = "passwords.json"
                    # If file exists, delete it.
                    if os.path.isfile(password_file):
                        os.remove(password_file)
                        print("[-] Removed %s" % password_file)
                    else:
                        # If it fails, inform the user.
                        print("[-] Error: %s file not found" % password_file)

                    user_data_file = "user_data.json"
                    # If file exists, delete it.
                    if os.path.isfile(user_data_file):
                        os.remove(user_data_file)
                        print("[-] Removed %s" % user_data_file)
                    else:
                        # If it fails, inform the user.
                        print("[-] Error: %s file not found" % user_data_file)

                    x = True
                elif confirm == 'n':
                    print("[*] Canceling...")
                    x = True
                else:
                    print("[-] ERROR: Please pick a valid option! (y or n)")


        elif choice == '6' or choice == 'exit':  # If a user wants to quit the program
            break

if __name__ == "__main__":
    main()