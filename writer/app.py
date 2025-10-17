# writer_app.py (FULL PATCHED v3)
# RFID Passkey Writer GUI
# Robust Windows handling: better retries, clearer errors, optional no-DTR and post-open stabilize.
# Requires: pip install pyserial

import time
import json
import os
import sys
from tkinter import (
    Tk, Label, Entry, Button, messagebox, filedialog,
    StringVar, OptionMenu, Text, END, Checkbutton, BooleanVar
)

try:
    import serial
    from serial.tools import list_ports
    from serial.serialutil import SerialException
except Exception as e:
    msg = (
        "PySerial is required but not available.\n\n"
        "Install with:\n    python -m pip install pyserial\n\n"
        f"Import error: {e}"
    )
    raise SystemExit(msg)

DEFAULT_BAUD = 115200

# Known VID/PID pairs for Uno & common clones (lowercase hex strings)
KNOWN_IDS = {
    ("2341", "0043"),  # Arduino SA Uno
    ("2341", "0001"),  # Arduino Uno (old)
    ("2a03", "0043"),  # Arduino.org Uno
    ("1a86", "7523"),  # QinHeng CH340/CH341
    ("0403", "6001"),  # FTDI FT232
}

def enumerate_ports():
    """Return (ports_list, preferred_port). Uses VID/PID and description heuristics."""
    ports = []
    preferred = None
    try:
        comlist = list_ports.comports()
    except Exception:
        comlist = []

    for p in comlist:
        name = p.device  # e.g., 'COM6'
        desc = (p.description or "").lower()
        vid = f"{p.vid:04x}" if p.vid is not None else ""
        pid = f"{p.pid:04x}" if p.pid is not None else ""
        ports.append(name)

        if preferred is None:
            if (vid, pid) in KNOWN_IDS:
                preferred = name
            elif any(k in desc for k in ("arduino", "ch340", "ch341", "usb-serial", "ftdi")):
                preferred = name

    if preferred is None and ports:
        preferred = ports[0]
    return ports, preferred

def validate_json_or_text(s):
    s = s.strip()
    if not s:
        return False, "Empty input"
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            if not isinstance(obj, dict):
                return False, "JSON must be an object"
            if not (("passkey_string" in obj) or ("token" in obj) or ("passkey" in obj)):
                return False, "Missing passkey key in JSON (passkey_string/token/passkey)"
            return True, s
        except Exception as e:
            return False, f"Invalid JSON: {e}"
    else:
        return True, s  # token string allowed

def _format_os_error(e: Exception) -> str:
    # Try to surface errno / winerror cleanly
    errno = getattr(e, "errno", None)
    winerror = getattr(e, "winerror", None)
    msg = str(e)
    parts = []
    if errno is not None:
        parts.append(f"errno={errno}")
    if winerror is not None:
        parts.append(f"winerror={winerror}")
    if parts:
        msg = f"{msg} ({', '.join(parts)})"
    # Friendly hints
    hint = ""
    s = str(e)
    if "Access is denied" in s or "WinError 5" in s or (errno == 13):
        hint = "\n(Hint: another app has the port open—close Serial Monitor/Plotter/VS Code/Putty/etc.)"
    elif "WinError 31" in s or "A device attached" in s or (winerror == 31):
        hint = "\n(Hint: cable/port/driver issue—try a different USB cable/port, disable USB power saving, reinstall driver.)"
    return msg + hint

def _open_serial_with_retries(com, baud, retries=10, base_delay=0.25):
    """Open a serial port with exponential backoff on common transient Windows errors."""
    last_err = None
    # wait briefly for stable enumeration (in case device is re-enumerating)
    t0 = time.time()
    while time.time() - t0 < 2.0:
        try:
            ports_now = [p.device for p in list_ports.comports()]
        except Exception:
            ports_now = []
        if com in ports_now:
            break
        time.sleep(0.08)

    for attempt in range(1, retries + 1):
        try:
            ser = serial.Serial(
                com,
                baudrate=baud,
                timeout=0.2,
                write_timeout=1,
                rtscts=False,
                dsrdtr=False,
                xonxoff=False,
            )
            return ser
        except Exception as e:
            last_err = e
            s = str(e)
            # transient Windows errors: access denied / device not functioning / sharing violation
            if any(k in s for k in ("WinError 5", "WinError 31", "Access is denied", "A device attached", "Sharing violation")):
                time.sleep(base_delay * attempt)  # backoff
                continue
            else:
                raise
    # Exhausted retries
    raise SerialException(_format_os_error(last_err))

def _do_exchange_once(com, payload_bytes, baud, timeout, do_reset, stabilize_after_open):
    """One open-send-read-close cycle. Returns decoded response string."""
    ser = _open_serial_with_retries(com, baud)
    try:
        time.sleep(0.05)
        if do_reset:
            try:
                ser.dtr = False
                time.sleep(0.05)
                ser.dtr = True
            except Exception:
                pass
        if stabilize_after_open:
            time.sleep(2.0)  # allow driver/board to settle fully

        ser.reset_input_buffer()
        ser.reset_output_buffer()

        ser.write(payload_bytes)
        ser.flush()

        start = time.time()
        buf = bytearray()
        while time.time() - start < timeout:
            try:
                n = ser.in_waiting
                if n:
                    buf.extend(ser.read(n))
            except Exception:
                break
            time.sleep(0.05)
        return buf.decode("utf-8", errors="ignore").strip()
    finally:
        try:
            ser.close()
        except Exception:
            pass

def send_line(com, line, baud=DEFAULT_BAUD, timeout=6.0, do_reset=True, stabilize_after_open=False):
    """
    Send one LF-terminated line and read back response.
    If we hit a transient Windows error (errno 13 / WinError 31) during I/O, we retry once end-to-end.
    """
    payload = (line.rstrip("\r\n") + "\n").encode("utf-8")
    try:
        return _do_exchange_once(com, payload, baud, timeout, do_reset, stabilize_after_open)
    except Exception as e1:
        # If it's a classic transient, wait and try one full reopen+resend
        se = str(e1)
        if any(k in se for k in ("errno=13", "WinError 31", "A device attached", "Access is denied", "WinError 5")):
            time.sleep(1.2)
            try:
                return _do_exchange_once(com, payload, baud, timeout, do_reset, stabilize_after_open)
            except Exception as e2:
                return "ERR: " + _format_os_error(e2)
        return "ERR: " + _format_os_error(e1)

# ---------- UI Handlers ----------
def choose_file():
    path = filedialog.askopenfilename(
        title="Select JSON file",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
    )
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

def refresh_ports():
    ports, preferred = enumerate_ports()
    menu["menu"].delete(0, "end")
    if ports:
        for p in ports:
            menu["menu"].add_command(label=p, command=lambda v=p: com_var.set(v))
        com_var.set(preferred or ports[0])
        status.set(f"Ports: {', '.join(ports)}")
    else:
        menu["menu"].add_command(label="", command=lambda: None)
        com_var.set("")
        status.set("No serial ports found. You can type COM name manually (e.g., COM6).")

def on_send():
    com_typed = manual_entry.get().strip()
    com = com_typed or com_var.get().strip()
    if not com:
        messagebox.showerror("Error", "Select or enter a COM port (e.g., COM6).")
        return

    raw = text.get("1.0", END).strip()
    ok, payload = validate_json_or_text(raw)
    if not ok:
        messagebox.showerror("Invalid Input", payload)
        return

    bytelen = len(payload.encode("utf-8"))
    if bytelen > 700:
        if not messagebox.askyesno(
            "Large payload",
            f"Payload is {bytelen} bytes. MIFARE Classic 1K data area fits ~720 bytes.\nContinue anyway?"
        ):
            return

    status.set(f"Sending to {com} at {DEFAULT_BAUD} baud...")
    root.update_idletasks()

    resp = send_line(
        com,
        payload,
        DEFAULT_BAUD,
        timeout=6.0,
        do_reset=not no_reset_var.get(),
        stabilize_after_open=stabilize_var.get()
    )

    messagebox.showinfo(
        "Writer Result",
        f"Sent {bytelen} bytes to {com}\n\nDevice says:\n{resp or '(no response)'}"
    )
    status.set("Ready.")

# ---------- UI ----------
root = Tk()
root.title("RFID Passkey Writer (Full-JSON)")

Label(root, text="COM Port:").grid(row=0, column=0, sticky="e", padx=6, pady=6)

ports, preferred = enumerate_ports()
com_var = StringVar(value=(preferred or (ports[0] if ports else "")))
menu = OptionMenu(root, com_var, *(ports if ports else [""]))
menu.grid(row=0, column=1, sticky="w", padx=6, pady=6)

Button(root, text="Refresh", command=refresh_ports).grid(row=0, column=2, padx=6, pady=6, sticky="w")

Label(root, text="or type COM:").grid(row=0, column=3, sticky="e", padx=6, pady=6)
manual_entry = Entry(root, width=10)
manual_entry.grid(row=0, column=4, sticky="w", padx=6, pady=6)

Label(root, text="Passkey JSON (or token string):").grid(row=1, column=0, columnspan=5, sticky="w", padx=6)
text = Text(root, width=84, height=14)
text.grid(row=2, column=0, columnspan=5, padx=6, pady=6)

Button(root, text="Browse JSON file…", command=choose_file).grid(row=3, column=0, padx=6, pady=6, sticky="w")
no_reset_var = BooleanVar(value=False)
Checkbutton(root, text="Open without reset (no DTR)", variable=no_reset_var).grid(row=3, column=1, padx=6, pady=6, sticky="w")
stabilize_var = BooleanVar(value=False)
Checkbutton(root, text="Stabilize after open (2 s)", variable=stabilize_var).grid(row=3, column=2, padx=6, pady=6, sticky="w")
Button(root, text="Write to Tag", command=on_send).grid(row=3, column=4, padx=6, pady=6, sticky="e")

status = StringVar(value=("Ports: " + ", ".join(ports)) if ports else "No serial ports found yet. Click Refresh or type COM (e.g., COM6).")
Label(root, textvariable=status, fg="gray").grid(row=4, column=0, columnspan=5, sticky="w", padx=6, pady=4)

root.mainloop()
