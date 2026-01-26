from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from random import choice, randint, shuffle
import csv
import pyperclip

#Cryptography imports
import base64
import secrets
import cryptography.exceptions
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Cryptography constants
KDF_ALGORITHM = hashes.SHA256()
KDF_LENGTH = 32
KDF_ITERATIONS = 120000

#using pipe with space for testing
DELIMITER = ","

#------------------------------ TASKS -----------------------------#
#Add decrypt_credentials() to handle decrypting when button is clicked
#Add decrypting an entry/row using the master password
#Add button for decrypted username and password to copy each to the clipboard
#Add a button to clear the clipboard in bottom right next to decrypt button
#Add show/hide password button for the master password
#Make decrypted username and password selectable but not editable
#Add tool tips like: the generate password button also copies the password to the clipboard
#Fix layout. columnconfigure/rowconfigure on the tab grid
#Add a messagebox to confirm closing the app and clear the clipboard. Tell the user closing clears clipboard
#When clicking on decrypt tab load the data.csv to ensure entries are up to date
#Seperate encrypt and decrypt functions to their own file

#Salts and Encrypts a string with a password. Returns ciphertext and salt
def encrypt(plaintext: str, password: str) -> (bytes, bytes):
    #Derive a symmetric key using the password and a fresh random salt
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt, iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    #Encrypt the message
    f = Fernet(base64.urlsafe_b64encode(key))
    ciphertext = f.encrypt(plaintext.encode("utf-8"))

    return ciphertext, salt

#Decrypts some ciphertext using the password and salt. Returns plaintext
def decrypt(ciphertext: bytes, password: str, salt: bytes) -> str:
    #Derive the symmetric key using the password and provided salt
    kdf = PBKDF2HMAC(algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt, iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    #Decrypt the message
    f = Fernet(base64.urlsafe_b64encode(key))
    try:
        plaintext = f.decrypt(ciphertext)
        return plaintext.decode("utf-8")
    except cryptography.fernet.InvalidToken as _:
        print(f"InvalidToken")
    except Exception as e:
        print(f"Unexpected error: {e}")

#Loads the data.csv and returns the data as a list of lists
def load_entries():
    try:
        with open("data.csv", mode="r", newline="") as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=DELIMITER)
            return list(csv_reader)
    except FileNotFoundError:
        print("data.csv not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

#Generates a strong password, inserts the password into the password_entry, and copies it to the clipboard
def generate_password():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    password_letters = [choice(letters) for _ in range(randint(8, 10))]
    password_numbers = [choice(numbers) for _ in range(randint(2, 4))]
    password_symbols = [choice(symbols) for _ in range(randint(2, 4))]

    password_list = password_letters + password_numbers + password_symbols
    shuffle(password_list)

    finished_password = "".join(password_list)
    password_entry.insert(0, finished_password)
    pyperclip.copy(finished_password)

#Clears input from all 3 entries
def clear_encrypt_entries():
    website_entry.delete(0, END)
    username_entry.delete(0, END)
    password_entry.delete(0, END)

#Validates that none of the entries are empty
def validate_encrypt_input():
    if len(website_entry.get()) > 0 and len(username_entry.get()) > 0 and len(password_entry.get()) > 0:
        return True
    else:
        messagebox.showwarning(title="Missing Input", message="Please make sure that all fields are filled out.")
        return False

#Saves the credentials entered to the data.csv file
def save_entry():
    if validate_encrypt_input():
        confirmed = messagebox.askokcancel(title=website_entry.get(),
                                            message=f"Username: {username_entry.get()}\n"
                                                    f"Password: {password_entry.get()}\n\n"
                                                    f"Would you like to save?")
        if confirmed:
            username_ciphertext, username_salt = encrypt(username_entry.get(), master_password_var.get())
            password_ciphertext, password_salt = encrypt(password_entry.get(), master_password_var.get())

            with open("data.csv", mode="a") as file:
                file.write(f"{website_entry.get()}{DELIMITER}"
                           f"{username_ciphertext}{DELIMITER}"
                           f"{username_salt}{DELIMITER}"
                           f"{password_ciphertext}{DELIMITER}"
                           f"{password_salt}\n")
            clear_encrypt_entries()

def toggle_show_master_pass():
    encrypt_show_state = master_pass_encrypt_entry.cget("show")
    decrypt_show_state = master_pass_decrypt_entry.cget("show")

    if encrypt_show_state or decrypt_show_state == "*":
        master_pass_encrypt_entry.configure(show="")
        master_pass_decrypt_entry.configure(show="")
        en_toggle_show_master_pass_button.configure(text="Hide Password")
        de_toggle_show_master_pass_button.configure(text="Hide Password")
    else:
        master_pass_encrypt_entry.configure(show="*")
        master_pass_decrypt_entry.configure(show="*")
        en_toggle_show_master_pass_button.configure(text="Show Password")
        de_toggle_show_master_pass_button.configure(text="Show Password")

# ---------------------------- UI Setup ------------------------------- #
#Main window
window = Tk()
window.title("Password Manager")
window.configure(padx=30, pady=20)

master_password_var = StringVar()

#Tabview
notebook = ttk.Notebook(master=window)
encrypt_frame = ttk.Frame(master=notebook)
decrypt_frame = ttk.Frame(master=notebook)

#Adding tabs
notebook.add(encrypt_frame, text="Encrypt")
notebook.add(decrypt_frame, text="Decrypt")

# ---------------------------------- Encrypt Tab ------------------------------- #
#Logo
canvas = Canvas(master=window, width=200, height=200)
logo_image = PhotoImage(file="logo.png")
canvas.create_image(100, 100, image=logo_image)

#Labels
master_pass_encrypt_label = Label(master=encrypt_frame, text="Master Password: ")
website_label = Label(master=encrypt_frame, text="Website: ")
username_label = Label(master=encrypt_frame, text="Email/Username: ")
password_label = Label(master=encrypt_frame, text="Password: ")

#Entries
master_pass_encrypt_entry = Entry(master=encrypt_frame, width=33, textvariable=master_password_var, show="*")
master_pass_encrypt_entry.focus()
website_entry = Entry(master=encrypt_frame, width=35)
username_entry = Entry(master=encrypt_frame, width=35)
password_entry = Entry(master=encrypt_frame, width=33)

#Buttons
en_toggle_show_master_pass_button = Button(master=encrypt_frame, text="Show Password", command=toggle_show_master_pass)
generate_button = Button(master=encrypt_frame, text="Generate Password", command=generate_password)
add_button = Button(master=encrypt_frame, text="Add", width=36, command=save_entry)

# ---------------------------------- Decrypt Tab ------------------------------- #
#Labels
master_pass_decrypt_label = Label(master=decrypt_frame, text="Master Password: ")
website_select_label = Label(master=decrypt_frame, text="Website: ")
decrypted_username_label = Label(master=decrypt_frame, text="Username: ")
decrypted_password_label = Label(master=decrypt_frame, text="Password: ")

#Entries
master_pass_decrypt_entry = Entry(master=decrypt_frame, width=35, textvariable=master_password_var, show="*")
decrypted_username_entry = Entry(master=decrypt_frame, width=35, state="readonly")
decrypted_password_entry = Entry(master=decrypt_frame, width=35, state="readonly")

#Buttons
de_toggle_show_master_pass_button = Button(master=decrypt_frame, text="Show Password", command=toggle_show_master_pass)
decrypted_copy_username_button = Button(master=decrypt_frame, text="Copy")
decrypted_copy_password_button = Button(master=decrypt_frame, text="Copy")
decrypt_button = Button(master=decrypt_frame, text="Decrypt")

#Temp testing/ needs to load on clicking decrypt tab
data = load_entries()
websites = [entry[0] for entry in data]
print(websites)

decrypt_dropdown = ttk.Combobox(master=decrypt_frame, values=websites, state="readonly")
decrypt_dropdown.set("Select a website")

# ---------------------------------- Layout ------------------------------- #
#Logo
canvas.pack()

#Tabview
notebook.pack(fill="both", expand=True)

encrypt_frame.grid_rowconfigure(0, weight=1)
encrypt_frame.grid_columnconfigure(0, weight=1)

decrypt_frame.grid_rowconfigure(0, weight=1)
decrypt_frame.grid_columnconfigure(0, weight=1)

#Encrypt Tab -------------------- #
#Labels
master_pass_encrypt_label.grid(row=0, column=0, sticky="E")
website_label.grid(row=1, column=0, sticky="E")
username_label.grid(row=2, column=0, sticky="E")
password_label.grid(row=3, column=0, sticky="E")

#Entries
master_pass_encrypt_entry.grid(row=0, column=1, sticky="WE")
website_entry.grid(row=1, column=1, columnspan=2, sticky="WE")
username_entry.grid(row=2, column=1, columnspan=2, sticky="WE")
password_entry.grid(row=3, column=1, sticky="WE")

#Buttons
en_toggle_show_master_pass_button.grid(row=0, column=2, sticky="WE")
generate_button.grid(row=3, column=2, sticky="WE")
add_button.grid(row=4, column=1, columnspan=2, sticky="WE")

#Decrypt Tab -------------------- #
#Labels
master_pass_decrypt_label.grid(row=0, column=0, sticky="E")
website_select_label.grid(row=1, column=0, sticky="E")
decrypted_username_label.grid(row=2, column=0, sticky="E")
decrypted_password_label.grid(row=3, column=0, sticky="E")

#Entries
master_pass_decrypt_entry.grid(row=0, column=1, sticky="WE")
decrypted_username_entry.grid(row=2, column=1, sticky="WE")
decrypted_password_entry.grid(row=3, column=1, sticky="WE")

#Buttons
de_toggle_show_master_pass_button.grid(row=0, column=2, sticky="WE")
decrypted_copy_username_button.grid(row=2, column=2, sticky="WE")
decrypted_copy_password_button.grid(row=3, column=2, sticky="WE")
decrypt_button.grid(row=4, column=1, columnspan=2, sticky="WE")

#Dropdown
decrypt_dropdown.grid(row=1, column=1, sticky="WE")

#checking values temp
cipher_text, u_salt = encrypt("plaintext", master_password_var.get())
cipher_text2, u_salt2 = encrypt("username+password", master_password_var.get())
print(f"cipher text: {cipher_text}\nunique salt: {u_salt}")
print(f"cipher text2: {cipher_text2}\nunique salt2: {u_salt2}")
plain_text = decrypt(cipher_text, master_password_var.get(), u_salt)
print(f"Output: {plain_text}")

window.mainloop()