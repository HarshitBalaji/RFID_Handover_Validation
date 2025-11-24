# **Blood Bank Cold-Chain IoT Handover POC**

This repository contains a working Proof-of-Concept demonstrating a secure workflow for **cold-chain logistics tracking** using:

* **ESP32 IoT devices (Box Units)**
* **A Truck Gateway running MQTT (Mosquitto) + Python Agent**
* **A Backend Server implementing Signed Passkeys, Order Validation, and Telemetry Logging**

The system integrates **device attestation, signed passkeys, access-controlled telemetry forwarding, and state machine–based validation**.

---

## 📦 Components Required

### **Hardware**

| Component                         | Qty       | Notes                                     |
| --------------------------------- | --------- | ----------------------------------------- |
| ESP32 Dev Board                   | ≥ 1       | Acts as “Box Unit”                        |
| DS18B20 temperature sensor        | 1 per box | Real telemetry input                      |
| MFRC522 RFID Reader               | 1 per box | Used to trigger passkey scans             |
| Raspberry Pi (4 or 5 recommended) | 1         | Truck Gateway running Mosquitto + agent   |
| USB Power                         | —         | For ESP + Pi                              |
| 4.7kΩ Resistor                    | 1         | Required for DS18B20                      |
| RFID Tags (NTAG/MIFARE)           | Optional  | Used to simulate sender/receiver passkeys |

### **Software**

| Component                                   | Version                              |
| ------------------------------------------- | ------------------------------------ |
| Python                                      | ≥ 3.10                               |
| FastAPI                                     | Latest compatible                    |
| Mosquitto MQTT Broker                       | ≥ 2.0                                |
| Arduino + ESP32 Board Support               | Latest                               |
| LittleFS Arduino Plugin                     | Required                             |
| Paho MQTT, Requests, Cryptography Libraries | Installed through `requirements.txt` |

---

## 📡 Hardware Wiring

### **RFID MFRC522 → ESP32**

| MFRC522 Pin | ESP32 Pin |
| ----------- | --------- |
| SDA / SS    | GPIO 5    |
| SCK         | GPIO 18   |
| MOSI        | GPIO 23   |
| MISO        | GPIO 19   |
| RST         | GPIO 27   |
| 3.3V        | 3.3V      |
| GND         | GND       |

### **DS18B20 → ESP32**

| Sensor Pin  | ESP32 Pin              |
| ----------- | ---------------------- |
| DQ (Signal) | GPIO 4                 |
| VCC         | 3.3V                   |
| GND         | GND                    |
| Pull-Up     | 4.7kΩ Between DQ ↔ VCC |

---

## ⚙️ System Setup

### **1️⃣ Clone Repository**

```bash
git clone <REPO_URL>
cd <REPO_DIR>
```

### **2️⃣ Python Environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### **3️⃣ Generate Certificates**

A script or command list will be provided under `scripts/generate_certs.sh`.
These generate:

| Certificate                            | Used By                |
| -------------------------------------- | ---------------------- |
| `mqtt_broker.crt/key`                  | Mosquitto              |
| `truck_client.crt/key`                 | Truck Agent            |
| `esp_client.crt/key`                   | ESP Box                |
| `server_privkey.pem/server_pubkey.pem` | Backend server signing |

### **4️⃣ Configure Files**

Update:

* `/config.yaml` on **server**
* `/TruckPi/config.yaml` on **truck**
* Update Wi-Fi + MQTT IP in `esp_edge.ino`

### **5️⃣ Place ESP Certs in LittleFS**

Upload:

```
/certs/ca.crt  
/certs/esp_client.crt  
/certs/esp_client.key  
```

---

## 🚚 Starting the System

### **A) Start Mosquitto on the Truck**

```bash
sudo systemctl restart mosquitto
sudo systemctl status mosquitto
```

### **B) Start Backend Server**

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

### **C) Start the Truck Agent**

```
python3 agent.py
```

### **D) Flash and Run ESP32**

Upload `esp_edge.ino` → open serial monitor → confirm:

```
WiFi Connected
MQTT Connected (TLS)
Telemetry Publishing...
```

---

## 🔧 Using the POC

### **1️⃣ Create an Order**

```bash
POST /create_order
```

Response contains a **sender passkey**.

### **2️⃣ Generate Receiver Passkey**

```bash
POST /generate_receiver_passkey/{order_id}
```

### **3️⃣ Trigger Scan**

On ESP serial monitor:

```
SCAN <PASSKEY_STRING>
```

OR tap RFID if configured.

### **4️⃣ Observe the Flow**

| Event                 | Expected Behavior                                    |
| --------------------- | ---------------------------------------------------- |
| Sender passkey used   | Box becomes “attached” to order, telemetry forwarded |
| Telemetry sent        | Stored on server                                     |
| Receiver passkey used | Box is detached, telemetry forwarding stops          |

---

## 🧰 Troubleshooting

| Issue                                          | Cause                            | Fix                                                 |
| ---------------------------------------------- | -------------------------------- | --------------------------------------------------- |
| ESP says `MQTT connect failed`                 | Cert mismatch or broker hostname | Ensure `/etc/hosts` contains `broker.example.local` |
| `422 Unprocessable Entity` on `/validate_scan` | Expired/old token                | Regenerate sender/receiver passkeys                 |
| No RFID response                               | Wiring or reader init issue      | Verify SPI wiring + run RFID self-test              |
| Telemetry not forwarding                       | Box not attached to order        | Scan sender passkey first                           |

---

## ⚠️ Known Limitations (POC)

| Limitation                                         | Notes                                      |
| -------------------------------------------------- | ------------------------------------------ |
| No HTTPS on FastAPI server                         | Application signatures handle authenticity |
| ESP disables TLS hostname verify (`setInsecure()`) | Acceptable for POC, noted for production   |
| Alerts channel not fully integrated in truck       | Future enhancement                         |
| RFID token contents not yet written in field       | Serial scan fallback supported             |

---

## 💬 Contributing, Feedback & Issues

This repository is meant to evolve.
If you:

* Found a bug
* Have improvement ideas
* Want to extend features

👉 **Please open an Issue on this repository — discussion is encouraged.**

---

## 📄 Citation

If this project supports your research, please cite the upcoming revised paper once published.
