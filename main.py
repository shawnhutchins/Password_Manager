from tkinter import *
# ---------------------------- PASSWORD GENERATOR ------------------------------- #

# ---------------------------- SAVE PASSWORD ------------------------------- #

# ---------------------------- UI SETUP ------------------------------- #
window = Tk()
window.title("Password Manager")
window.configure( padx=20, pady=20)

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
username_entry = Entry(master=window, width=35)
password_entry = Entry(master=window, width=21)

#Grid ---------------------------------------------------
canvas.grid(row=0, column=1)
#Labels
website_label.grid(row=1, column=0)
username_label.grid(row=2, column=0)
password_label.grid(row=3, column=0)

window.mainloop()