# writer_app.py (PATCHED)
# - Choose COM port & browse JSON file (or paste text)
# - Sends one LF-terminated line to Arduino
# - Shows device responses (OK:WRITE / OK:VERIFY / ERR:...)
#
# Requires: pip install pyserial

import serial, time, json, glob, sys, os
from tkinter import Tk, Label, Entry, Button, messagebox, filedialog, StringVar, OptionMenu, Text, END, DISABLED, NORMAL

DEFAULT_BAUD = 115200

def list_serial_ports():
    if sys.platform.startswith("win"):
        ports = [f"COM{i}" for i in range(1, 256)]
    elif sys.platform.startswith(("linux", "cygwin")):
        ports = glob.glob("/dev/tty[A-Za-z]*")
    elif sys.platform.startswith("darwin"):
        ports = glob.glob("/dev/tty.*")
    else:
        ports = []
    out = []
    for p in ports:
        try:
            s = serial.Serial(p)
            s.close()
            out.append(p)
        except Exception:
            pass
    return out

def send_line(com, line, baud=DEFAULT_BAUD, timeout=3.0):
    try:
        ser = serial.Serial(com, baudrate=baud, timeout=0.2)
    except Exception as e:
        return f"ERR: open {com}: {e}"
    time.sleep(0.8)  # let Arduino reset (DTR toggle)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    ser.write((line.rstrip("\r\n") + "\n").encode("utf-8"))
    ser.flush()
    start = time.time()
    buf = ""
    while time.time() - start < timeout:
        try:
            if ser.in_waiting:
                buf += ser.read(ser.in_waiting).decode(errors="ignore")
        except Exception:
            break
        time.sleep(0.05)
    ser.close()
    return buf.strip()

def validate_json_or_text(s):
    s = s.strip()
    if not s:
        return False, "Empty input"
    # Accept either full JSON or token string
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            # minimal full-JSON sanity
            if not isinstance(obj, dict):
                return False, "JSON must be an object"
            if not (("passkey_string" in obj) or ("token" in obj) or ("passkey" in obj)):
                return False, "Missing passkey key in JSON (passkey_string/token/passkey)"
            # keep as is (no reformatting) to preserve byte-exact content
            return True, s
        except Exception as e:
            return False, f"Invalid JSON: {e}"
    else:
        # token-only fallback: wrap? No—writer should store exactly what server generated.
        return True, s

def choose_file():
    path = filedialog.askopenfilename(title="Select JSON file",
                                      filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
    if not path:
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read()
        text.delete("1.0", END)
        text.insert("1.0", data)
        status.set(f"Loaded file: {os.path.basename(path)} ({len(data.encode('utf-8'))} bytes)")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load file:\n{e}")

def on_send():
    com = com_var.get().strip()
    if not com:
        messagebox.showerror("Error", "Select a COM port")
        return
    raw = text.get("1.0", END).strip()
    ok, payload = validate_json_or_text(raw)
    if not ok:
        messagebox.showerror("Invalid Input", payload)
        return
    bytelen = len(payload.encode("utf-8"))
    if bytelen > 700:
        if not messagebox.askyesno("Large payload",
                                   f"Payload is {bytelen} bytes. MIFARE Classic 1K data area fits ~720 bytes.\n"
                                   f"Continue anyway?"):
            return
    resp = send_line(com, payload, DEFAULT_BAUD, timeout=5.0)
    messagebox.showinfo("Writer Result",
                        f"Sent {bytelen} bytes to {com}\n\nDevice says:\n{resp or '(no response)'}")

# UI
root = Tk()
root.title("RFID Passkey Writer (Full-JSON)")

Label(root, text="COM Port:").grid(row=0, column=0, sticky="e", padx=6, pady=6)
ports = list_serial_ports()
com_var = StringVar(value=(ports[0] if ports else ""))
menu = OptionMenu(root, com_var, *ports) if ports else OptionMenu(root, com_var, "")
menu.grid(row=0, column=1, sticky="w", padx=6, pady=6)

Button(root, text="Refresh", command=lambda: [menu["menu"].delete(0, "end"),
                                              [menu["menu"].add_command(label=p, command=lambda v=p: com_var.set(v)) for p in list_serial_ports()],
                                              com_var.set((list_serial_ports()[0] if list_serial_ports() else ""))]).grid(row=0, column=2, padx=6)

Label(root, text="Passkey JSON (or token string):").grid(row=1, column=0, columnspan=3, sticky="w", padx=6)
text = Text(root, width=70, height=12)
text.grid(row=2, column=0, columnspan=3, padx=6, pady=6)

Button(root, text="Browse JSON file…", command=choose_file).grid(row=3, column=0, padx=6, pady=6, sticky="w")
Button(root, text="Write to Tag", command=on_send).grid(row=3, column=2, padx=6, pady=6, sticky="e")

status = StringVar(value="Ready.")
Label(root, textvariable=status, fg="gray").grid(row=4, column=0, columnspan=3, sticky="w", padx=6, pady=4)

root.mainloop()
