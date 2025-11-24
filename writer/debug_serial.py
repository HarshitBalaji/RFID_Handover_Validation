import serial, time
s = serial.Serial("COM5", 115200, timeout=1)
time.sleep(2)           # let it settle
s.write(b"ping\n")
print(s.read(128))
s.close()
