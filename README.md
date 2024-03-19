# Password-Manager
CLI Password Manager made in python

Usage:
    python3 password-manager.py

Features:
    A simple password manager, stores passwords securely by encrypting them with fernet.
    Register and log in using a master password.
    When creating new passwords, can either choose your own or generate a new secure random password using secrets module.
    Also has a password strength checker, which displays password strength whenever a new password is generated or choosen.
    Can also delete the database files by using cleanup feature.

Main Screen Options:
    1. Register a new master password
    2. Login to an existing account
    3. Generate a random password
    4. Test a passwords strength
    5. Reset Database (keys and passwords)
    6. Quit password manager

To-do:
    Add the options to have more than one password database at a time.
    Error Handling
    Salting for master password
    GUI? (Maybe)

