# password_manager
Python_Project_FHNW

A simple password manager application that securely stores and manages passwords using RSA encryption.  

## Features
- Store and manage platform passwords securely.
- Encrypt and decrypt passwords with RSA encryption.
- Add password.
- Update and delete existing password.
- Modify the login key to enhance security.
- The user can change the login key.
- If the login key file or decryption file is missing, the program will reset and delete all stored password for data security reassons.

## How to run this program

**Method 1: Run the Program Directly**

I have already packaged the program using PyInstaller. You can run the main.exe file directly on your computer.

**Method 2: Manually Install Dependencies and Run the Python Code**
- Clone or download the project file
- Ensure you have Python 3.10 or higher installed
- Install the required dependencies (in **requirements.txt**)
- Run the **main.py** file
- Upon startup, the program will ask for a secret key. The default key is **password**.


