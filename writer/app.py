# writer_serial.py
import serial
import time
import json
from tkinter import Tk, Label, Entry, Button, messagebox

SERIAL_PORT = "COM3"  # change to your Arduino COM port
BAUD = 115200

def send_passkey_to_arduino(com, passkey_str):
    try:
        ser = serial.Serial(com, BAUD, timeout=1)
        time.sleep(1)
        ser.write((passkey_str + "\n").encode())
        time.sleep(0.2)
        # optionally read response lines
        resp = ""
        start = time.time()
        while time.time() - start < 2:
            if ser.in_waiting:
                resp += ser.readline().decode(errors='ignore')
        ser.close()
        return resp
    except Exception as e:
        return f"ERR: {e}"

def on_send():
    pk = entry.get().strip()
    if not pk:
        messagebox.showerror("Error","Enter passkey string")
        return
    res = send_passkey_to_arduino(SERIAL_PORT, pk)
    messagebox.showinfo("Result", f"Arduino response:\n{res}")

root = Tk()
root.title("RFID Passkey Writer")
Label(root, text="Passkey string:").grid(row=0, column=0, padx=6, pady=6)
entry = Entry(root, width=40)
entry.grid(row=0, column=1, padx=6, pady=6)
Button(root, text="Write to tag (Arduino must be connected)", command=on_send).grid(row=1, column=0, columnspan=2, pady=8)
root.mainloop()
