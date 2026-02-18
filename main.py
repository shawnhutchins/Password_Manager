from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from random import choice, randint, shuffle
import json
import pyperclip
from pwcryptography import *

#Storing loaded data
data = {}

#------------------------------ TASKS -----------------------------#
#Handel errors when clicking on the decrypt tab when there is no data.json file
#Find a good place to do an initial load of the json into the global data variable
#Verify that comments are still correct after moving to using json data etc.
#Consider adding autocomplete to the decrypt dropdown input
#Refactor to use a class for each tab
#Add tool tips example: the generate password button also copies the password to the clipboard
#Does data need to be a global?

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

#Clears plain text username and password entries
def clear_decrypt_entries():
    decrypted_username_entry.configure(state="normal")
    decrypted_username_entry.delete(0, END)
    decrypted_username_entry.configure(state="readonly")

    decrypted_password_entry.configure(state="normal")
    decrypted_password_entry.delete(0, END)
    decrypted_password_entry.configure(state="readonly")

#Validates that none of the entries are empty
def validate_encrypt_input():
    if len(master_pass_encrypt_entry.get()) > 0 and len(website_entry.get()) > 0 and len(username_entry.get()) > 0 and len(password_entry.get()) > 0:
        return True
    else:
        messagebox.showwarning(title="Missing Input", message="Please make sure that all fields are filled out.")
        return False

#Validates that master password is not empty and the dropdown is set to a row
def validate_decrypt_input():
    if len(master_pass_decrypt_entry.get()) > 0 and decrypt_dropdown.get() != "Select a website":
        if website_status_var.get() == "Found":
            return True
        else:
            messagebox.showwarning(title="Input not found", message="The entered website was not found.")
            return False
    else:
        messagebox.showwarning(title="Missing Input", message="Please make sure that all fields are filled out.")
        return False

#Validates that the value entered into the decrypt website dropdown is a key in the loaded json data
def update_website_key_status(*args):
    key = decrypt_dropdown.get()
    if key in data:
        website_status_label.config(fg="green")
        website_status_var.set("Found")
    else:
        website_status_label.config(fg="red")
        website_status_var.set("Not Found")

#Saves the credentials entered to the data.csv file
def save_entry():
    if validate_encrypt_input():
        username_ciphertext, username_salt = encrypt(username_entry.get(), master_password_var.get())
        password_ciphertext, password_salt = encrypt(password_entry.get(), master_password_var.get())

        website = website_entry.get()
        username_ciphertext_str = username_ciphertext.decode("utf-8")
        username_salt_str = base64.b64encode(username_salt).decode("utf-8")
        password_ciphertext_str = password_ciphertext.decode("utf-8")
        password_salt_str = base64.b64encode(password_salt).decode("utf-8")

        new_data = {
            website: {
                "username": {
                    "ciphertext": username_ciphertext_str,
                    "salt": username_salt_str,
                },
                "password": {
                    "ciphertext": password_ciphertext_str,
                    "salt": password_salt_str,
                }
            }
        }

        try:
            #Try to read in the saved json
            with open("data.json", mode="r") as data_file:
                json_data = json.load(data_file)
        except FileNotFoundError:
            #If the file does not exist, create the file and write new_data to the file
            with open("data.json", "w") as data_file:
                #noinspection PyTypeChecker
                json.dump(new_data, data_file, indent=4)
        else:
            #Else the file exists and update json_data with the new_data
            json_data.update(new_data)

            #Write the json_date with the update to the file
            with open("data.json", mode="w") as data_file:
                #noinspection PyTypeChecker
                json.dump(json_data, data_file, indent=4)
        finally:
            clear_encrypt_entries()

#Loads the data.json and returns the data as json
def load_entries():
    try:
        with open("data.json", mode="r") as data_file:
            json_data = json.load(data_file)
            return json_data
    except FileNotFoundError:
        print("data.json not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

#Runs on tab change, clears entries and loads json data into the global data variable
def on_tab_selected(event):
    notebook_widget = event.widget
    selected_tab_id = notebook_widget.select()
    tab_text = notebook_widget.tab(selected_tab_id, "text")
    if tab_text == "Encrypt":
        clear_decrypt_entries()
    elif tab_text == "Decrypt":
        global data
        data = load_entries()
        if not data:
            notebook.select(0)
            messagebox.showwarning(title="Missing data", message="There are no credentials to decrypt, please add an entry.")
        else:
            websites = list(data.keys())
            decrypt_dropdown["values"] = websites
    else:
        print("Out Of Bounds: Not a valid tab.")

#Selects the text in the dropdown when it gains focus in
def on_dropdown_focus_in(event):
    dropdown_widget = event.widget
    dropdown_widget.selection_range(0, "end")

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
    if validate_decrypt_input():
        credential = decrypt_dropdown.get()

        username_ciphertext = data[credential]["username"]["ciphertext"].encode("utf-8")
        username_salt = base64.b64decode(data[credential]["username"]["salt"].encode("utf-8"))
        password_ciphertext = data[credential]["password"]["ciphertext"].encode("utf-8")
        password_salt = base64.b64decode(data[credential]["password"]["salt"].encode("utf-8"))

        username_plaintext = decrypt(username_ciphertext, master_password_var.get(), username_salt)
        password_plaintext = decrypt(password_ciphertext, master_password_var.get(), password_salt)

        #Checking if username and password were successfully decrypted
        if username_plaintext and password_plaintext:
            decrypted_username_entry.configure(state="normal")
            decrypted_username_entry.delete(0, "end")
            decrypted_username_entry.insert(0, username_plaintext)
            decrypted_username_entry.configure(state="readonly")

            decrypted_password_entry.configure(state="normal")
            decrypted_password_entry.delete(0, "end")
            decrypted_password_entry.insert(0, password_plaintext)
            decrypted_password_entry.configure(state="readonly")
        else:
            messagebox.showerror("Error", "Incorrect Master Password for the chosen credentials.")

#Username copy button command
def copy_decrypted_username():
    pyperclip.copy(decrypted_username_entry.get())

#Password copy button command
def copy_decrypted_password():
    pyperclip.copy(decrypted_password_entry.get())

#Clears the clipboard by copying an empty string
def clear_clipboard():
    pyperclip.copy("")

#Confirms closing the app with a massage box
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

#Master password variable used for both encrypt and decrypt tabs
master_password_var = StringVar()

decrypt_dropdown_var = StringVar(value="Select a website")
decrypt_dropdown_var.trace_add("write", update_website_key_status)
website_status_var = StringVar(value="...")

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
website_status_label = Label(master=decrypt_frame, textvariable=website_status_var)
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
decrypt_dropdown = ttk.Combobox(master=decrypt_frame, textvariable=decrypt_dropdown_var)

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
website_status_label.grid(row=1, column=2, sticky="W")
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

#Events
notebook.bind("<<NotebookTabChanged>>", on_tab_selected)
decrypt_dropdown.bind("<FocusIn>", on_dropdown_focus_in)

window.mainloop()