from tkinter import *
from tkinter import messagebox

DEFAULT_USERNAME = "example@gmail.com"
# ---------------------------- PASSWORD GENERATOR ------------------------------- #

# ---------------------------- SAVE PASSWORD ------------------------------- #
def clear_entries():
    website_entry.delete(0, END)
    #username_entry.delete(0, END)
    password_entry.delete(0, END)

def save_entry():
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    messagebox.askokcancel(title=website, message=f"Username: {username}\nPassword: {password}\n\n"
                                                  f"Would you like to save?")

    with open("data.txt", "a") as file:
        file.write(f"{website},{username},{password}\n")
    clear_entries()

# ---------------------------- UI SETUP ------------------------------- #
window = Tk()
window.title("Password Manager")
window.configure(padx=50, pady=50)

#Logo
canvas = Canvas(master=window, width=200, height=200)
logo_image = PhotoImage(file="logo.png")
canvas.create_image(100, 100, image=logo_image)

#Labels
website_label = Label(master=window, text="Website:")
username_label = Label(master=window, text="Email/Username:")
password_label = Label(master=window, text="Password:")

#Entries
website_entry = Entry(master=window, width=35)
website_entry.focus()
username_entry = Entry(master=window, width=35)
username_entry.insert(0, DEFAULT_USERNAME)
password_entry = Entry(master=window, width=33)

#Buttons
generate_button = Button(master=window, text="Generate Password")
add_button = Button(master=window, text="Add", width=36, command=save_entry)

#Grid ---------------------------------------------------
canvas.grid(row=0, column=1)
#Labels
website_label.grid(row=1, column=0, sticky="E")
username_label.grid(row=2, column=0, sticky="E")
password_label.grid(row=3, column=0, sticky="E")
#Entries
website_entry.grid(row=1, column=1, columnspan=2, sticky="WE")
username_entry.grid(row=2, column=1, columnspan=2, sticky="WE")
password_entry.grid(row=3, column=1, sticky="W")
#Buttons
generate_button.grid(row=3, column=2, sticky="W")
add_button.grid(row=4, column=1, columnspan=2, sticky="WE")

window.mainloop()