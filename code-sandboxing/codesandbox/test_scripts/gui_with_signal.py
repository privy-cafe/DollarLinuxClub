"""
Some old mypy questions run tests after the GUI has been destroyed, so test for that output
"""


from tkinter import Tk, Label, Button
from signal import signal, SIGTERM, SIGINT

class SignalGUI:
    def __init__(self, master):
        self.master = master
        master.title("A simple GUI")

        self.label = Label(master, text="This is our first GUI! Rendered from the server!!")
        self.label.pack()

        self.greet_button = Button(master, text="Greet", command=self.greet)
        self.greet_button.pack()

        self.close_button = Button(master, text="Close", command=master.quit)
        self.close_button.pack()

    def greet(self):
        print("Greetings!")

root = Tk()
my_gui = SignalGUI(root)

def poll():
    root.after(500, poll)
root.after(500, poll)

def signal_handler(signal, frame):
    """ Print some output to be captured by code-sandbox """
    root.destroy()

    print("Output from signal handler")

signal(SIGTERM, signal_handler)
signal(SIGINT, signal_handler)


root.mainloop()
