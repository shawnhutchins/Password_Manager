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

#Temp remove when moving to JSON
DELIMITER = ","

#Storing loaded data
data = []

#------------------------------ TASKS -----------------------------#
#Does data need to be a global?
#Clear Decrypt tab plain text entries when clicking on the encrypt tab and reset the dropdown
#Verify inputs for the decrypt tab before allowing decryption. dropdown selection, master password filled
#When there is an error with validating the inputs for the decrypt tab use a messagebox to tell the user
#Add tool tips like: the generate password button also copies the password to the clipboard
#Catch when the wrong master password is used for a given row and alert the user
#Seperate encrypt and decrypt functions to their own file
#Refactor to use a class for each tab

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

            username_ciphertext_str = username_ciphertext.decode("utf-8")
            username_salt_str = base64.b64encode(username_salt).decode("utf-8")
            password_ciphertext_str = password_ciphertext.decode("utf-8")
            password_salt_str = base64.b64encode(password_salt).decode("utf-8")

            with open("data.csv", mode="a") as file:
                file.write(f"{website_entry.get()}{DELIMITER}"
                           f"{username_ciphertext_str}{DELIMITER}"
                           f"{username_salt_str}{DELIMITER}"
                           f"{password_ciphertext_str}{DELIMITER}"
                           f"{password_salt_str}\n")
            clear_encrypt_entries()

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

def on_tab_selected(event):
    notebook_widget = event.widget
    selected_tab_id = notebook_widget.select()
    tab_text = notebook_widget.tab(selected_tab_id, "text")
    if tab_text == "Encrypt":
        print("Encrypt Tab Selected")
    elif tab_text == "Decrypt":
        global data
        data = load_entries()
        try:
            websites = [entry[0] for entry in data]
            decrypt_dropdown["values"] = websites
        except Exception as e:
            print(f"Unexpected error: {e}")
        print("Decrypt Tab Selected")
    else:
        print("Out Of Bounds: Not a valid tab.")

#Toggles showing the master password on both tabs
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

#Decrypts the selected row and sets the username/password entries to their respective values
def decrypt_credentials():
    credential = decrypt_dropdown.get()
    row = [row for row in data if row[0] == credential]

    username_ciphertext = row[0][1].encode("utf-8")
    username_salt = base64.b64decode(row[0][2].encode("utf-8"))
    password_ciphertext = row[0][3].encode("utf-8")
    password_salt = base64.b64decode(row[0][4].encode("utf-8"))

    username_plaintext = decrypt(username_ciphertext, master_password_var.get(), username_salt)
    password_plaintext = decrypt(password_ciphertext, master_password_var.get(), password_salt)

    decrypted_username_entry.configure(state="normal")
    decrypted_username_entry.delete(0, "end")
    decrypted_username_entry.insert(0, username_plaintext)
    decrypted_username_entry.configure(state="readonly")

    decrypted_password_entry.configure(state="normal")
    decrypted_password_entry.delete(0, "end")
    decrypted_password_entry.insert(0, password_plaintext)
    decrypted_password_entry.configure(state="readonly")

#Username copy button command
def copy_decrypted_username():
    pyperclip.copy(decrypted_username_entry.get())

#Password copy button command
def copy_decrypted_password():
    pyperclip.copy(decrypted_password_entry.get())

def clear_clipboard():
    pyperclip.copy("")

def confirm_close():
    if messagebox.askokcancel("Exit", "The clipboard will be erased.\nAre you sure you want to quit?"):
        #Clear the clipboard
        pyperclip.copy("")
        #Close the window/app
        window.destroy()

# ---------------------------- UI Setup ------------------------------- #
#Main window
window = Tk()
window.title("Password Manager")
window.configure(padx=30, pady=20)
window.protocol("WM_DELETE_WINDOW", confirm_close)

master_password_var = StringVar()

#Tabview
notebook = ttk.Notebook(master=window)
encrypt_frame = ttk.Frame(master=notebook)
decrypt_frame = ttk.Frame(master=notebook)

#Adding tabs
notebook.add(encrypt_frame, text="Encrypt")
notebook.add(decrypt_frame, text="Decrypt")

#Logo
canvas = Canvas(master=window, width=200, height=200)
logo_image = PhotoImage(file="logo.png")
canvas.create_image(100, 100, image=logo_image)

# ---------------------------------- Encrypt Tab ------------------------------- #

#Labels
master_pass_encrypt_label = Label(master=encrypt_frame, text="Master Password: ")
website_label = Label(master=encrypt_frame, text="Website: ")
username_label = Label(master=encrypt_frame, text="Username: ")
password_label = Label(master=encrypt_frame, text="Password: ")

#Entries
master_pass_encrypt_entry = Entry(master=encrypt_frame, textvariable=master_password_var, show="*", width=33)
master_pass_encrypt_entry.focus()
website_entry = Entry(master=encrypt_frame)
username_entry = Entry(master=encrypt_frame)
password_entry = Entry(master=encrypt_frame)

#Buttons
en_toggle_show_master_pass_button = Button(master=encrypt_frame, text="Show Password", command=toggle_show_master_pass, width=16)
generate_button = Button(master=encrypt_frame, text="Generate Password", command=generate_password)
add_button = Button(master=encrypt_frame, text="Add", command=save_entry)
en_clear_clipboard_button = Button(master=encrypt_frame, text="Clear Clipboard", command=clear_clipboard)

# ---------------------------------- Decrypt Tab ------------------------------- #
#Labels
master_pass_decrypt_label = Label(master=decrypt_frame, text="Master Password: ")
website_select_label = Label(master=decrypt_frame, text="Website: ")
decrypted_username_label = Label(master=decrypt_frame, text="Username: ")
decrypted_password_label = Label(master=decrypt_frame, text="Password: ")

#Entries
master_pass_decrypt_entry = Entry(master=decrypt_frame, textvariable=master_password_var, show="*", width=33)
decrypted_username_entry = Entry(master=decrypt_frame, state="readonly")
decrypted_password_entry = Entry(master=decrypt_frame, state="readonly")

#Buttons
de_toggle_show_master_pass_button = Button(master=decrypt_frame, text="Show Password", command=toggle_show_master_pass, width=16)
copy_decrypted_username_button = Button(master=decrypt_frame, text="Copy", command=copy_decrypted_username)
copy_decrypted_password_button = Button(master=decrypt_frame, text="Copy", command=copy_decrypted_password)
decrypt_button = Button(master=decrypt_frame, text="Decrypt", command=decrypt_credentials)
de_clear_clipboard_button = Button(master=decrypt_frame, text="Clear Clipboard", command=clear_clipboard)

#Dropdown / Values are set when clicking on the Decrypt tab
decrypt_dropdown = ttk.Combobox(master=decrypt_frame, state="readonly")
decrypt_dropdown.set("Select a website")

# ---------------------------------- Layout ------------------------------- #
#Logo
canvas.pack()

#Tabview
notebook.pack(fill="x", expand=True)

#Setting grid row 5 weight to not add extra padding to the visible rows
encrypt_frame.grid_rowconfigure(5, weight=1)
encrypt_frame.grid_columnconfigure(1, weight=1)

#Setting grid row 5 weight to not add extra padding to the visible rows
decrypt_frame.grid_rowconfigure(5, weight=1)
decrypt_frame.grid_columnconfigure(1, weight=1)

#Encrypt Tab -------------------- #
#Labels
master_pass_encrypt_label.grid(row=0, column=0, sticky="E")
website_label.grid(row=1, column=0, sticky="E")
username_label.grid(row=2, column=0, sticky="E")
password_label.grid(row=3, column=0, sticky="E")

#Entries
master_pass_encrypt_entry.grid(row=0, column=1, sticky="WE")
website_entry.grid(row=1, column=1, sticky="WE")
username_entry.grid(row=2, column=1, sticky="WE", pady=(3, 4))
password_entry.grid(row=3, column=1, sticky="WE")

#Buttons
en_toggle_show_master_pass_button.grid(row=0, column=2, sticky="WE")
generate_button.grid(row=3, column=2, sticky="WE")
add_button.grid(row=4, column=1, sticky="WE")
en_clear_clipboard_button.grid(row=4, column=2, sticky="WE")

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
copy_decrypted_username_button.grid(row=2, column=2, sticky="WE")
copy_decrypted_password_button.grid(row=3, column=2, sticky="WE")
decrypt_button.grid(row=4, column=1, sticky="WE")
de_clear_clipboard_button.grid(row=4, column=2, sticky="WE")

#Dropdown
decrypt_dropdown.grid(row=1, column=1, sticky="WE")

#Event
notebook.bind("<<NotebookTabChanged>>", on_tab_selected)

window.mainloop()