from tkinter import *
import csv

DEFAULT_USERNAME = "example@gmail.com"
# ---------------------------- PASSWORD GENERATOR ------------------------------- #

# ---------------------------- SAVE PASSWORD ------------------------------- #
def clear_entries():
    website_data.set("")
    #username_data.set("")
    password_data.set("")

def save_entry():
    data = [website_data.get(), username_data.get(), password_data.get()]
    with open("data.txt", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(data)
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

#Entry Variables
website_data = StringVar()
username_data = StringVar()
password_data = StringVar()

#Entries
website_entry = Entry(master=window, width=35, textvariable=website_data)
website_entry.focus()
username_entry = Entry(master=window, width=35, textvariable=username_data)
username_data.set(DEFAULT_USERNAME)
password_entry = Entry(master=window, width=33, textvariable=password_data)

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