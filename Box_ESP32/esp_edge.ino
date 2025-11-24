/*
 * esp_edge.ino (POC, 3 channels + RFID + DS18B20, NO lookup / NO order on box)
 *
 * ESP32 edge node:
 *  - Connects to WiFi
 *  - Uses MQTT over TLS (port 8883) to truck Pi (Mosquitto)
 *  - Loads CA, client cert, and key from LittleFS:
 *       /certs/ca.crt
 *       /certs/esp_client.crt
 *       /certs/esp_client.key
 *
 * MQTT topics:
 *   boxes/<BOX_ID>/telemetry   -- periodic temperature + metadata
 *   boxes/<BOX_ID>/alerts      -- temp out of range, etc.
 *   boxes/<BOX_ID>/scan        -- passkey scans from RFID / Serial
 *
 * IMPORTANT DESIGN POINT:
 *   - Box does NOT know order_id.
 *   - Box does NOT map RFID → order.
 *   - Box ONLY sends:
 *        {
 *          "box_id": "<BOX_ID>",
 *          "passkey_string": "<whatever RFID/Serial gave>",
 *          "ts": <device timestamp>
 *        }
 *     to MQTT topic boxes/<BOX_ID>/scan.
 *
 * Temperature:
 *   DS18B20 on a OneWire pin (change PIN_TEMP if needed).
 *
 * RFID:
 *   MFRC522 via SPI to read UID or tag data and treat it as "passkey_string".
 */

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <LittleFS.h>

#include <SPI.h>
#include <MFRC522.h>

#include <OneWire.h>
#include <DallasTemperature.h>

// ----------- CONFIG (EDIT THESE) -----------

const char* WIFI_SSID     = "YourWiFiSSID";
const char* WIFI_PASSWORD = "Password123";

// For POC, use the Pi's LAN IP directly, e.g. "192.168.1.50"
const char* MQTT_HOST = "TRUCK_PI_IP_ADDRESS";
const uint16_t MQTT_PORT = 8883;

// Logical IDs used in messages
const char* BOX_ID   = "BOX-001";

// Period for telemetry in ms
const unsigned long TELEMETRY_INTERVAL_MS = 5000;  // 5 seconds

// Temperature sensor (DS18B20) pin
#define PIN_TEMP 4
OneWire oneWire(PIN_TEMP);
DallasTemperature tempSensors(&oneWire);

// Temperature alert thresholds (adjust for your cold chain)
const float TEMP_LOW_LIMIT  = 2.0f;
const float TEMP_HIGH_LIMIT = 8.0f;

// RFID (MFRC522) pin mapping for ESP32 (ADJUST TO YOUR WIRING)
#define RFID_SS_PIN  5    // SDA / SS
#define RFID_RST_PIN 27   // RST
MFRC522 mfrc522(RFID_SS_PIN, RFID_RST_PIN);

// -------------------------------------------

WiFiClientSecure secureClient;
PubSubClient mqttClient(secureClient);

unsigned long lastTelemetryMs = 0;

// Track last seen UID so we don't fire repeatedly while card is held
String lastRfidValue = "";
unsigned long lastRfidTimeMs = 0;
const unsigned long RFID_RETRIGGER_MS = 2000;  // minimum gap between same tag scans

// ---------- LittleFS helpers ----------

String readFileToString(const char* path) {
  File f = LittleFS.open(path, "r");
  if (!f) {
    Serial.print("Failed to open file: ");
    Serial.println(path);
    return String();
  }
  String content;
  while (f.available()) {
    content += char(f.read());
  }
  f.close();
  return content;
}

// ---------- WiFi / TLS / MQTT ----------

void connectWiFi() {
  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("WiFi connected. IP: ");
  Serial.println(WiFi.localIP());
}

bool configureTLSFromFS() {
  Serial.println("Mounting LittleFS...");
  if (!LittleFS.begin(true)) {  // true => format if mount fails (POC)
    Serial.println("LittleFS mount failed");
    return false;
  }
  Serial.println("LittleFS mounted");

  String ca   = readFileToString("/ca.crt");
  String cert = readFileToString("/esp_client.crt");
  String key  = readFileToString("/esp_client.key");

  Serial.printf("CA len: %d, cert len: %d, key len: %d\n",
                ca.length(), cert.length(), key.length());

  if (ca.length() == 0 || cert.length() == 0 || key.length() == 0) {
    Serial.println("Missing cert/key files in /certs");
    return false;
  }

  secureClient.setCACert(ca.c_str());
  secureClient.setCertificate(cert.c_str());
  secureClient.setPrivateKey(key.c_str());
  secureClient.setTimeout(5000);

  // POC ONLY: disable hostname verification, because we're using IP but
  // the broker cert CN is something like broker.example.local.
  // Remove this and use proper DNS in a production setup.
  secureClient.setInsecure();

  Serial.println("TLS configured from LittleFS");
  return true;
}

void connectMQTT() {
  while (!mqttClient.connected()) {
    Serial.printf("Connecting to MQTT(TLS) at %s:%d ...\n", MQTT_HOST, MQTT_PORT);
    String clientId = "esp_edge_" + String((uint32_t)ESP.getEfuseMac(), HEX);
    if (mqttClient.connect(clientId.c_str())) {
      Serial.println("MQTT connected");
    } else {
      Serial.print("MQTT connect failed, state=");
      Serial.println(mqttClient.state());
      delay(2000);
    }
  }
}

// ---------- Temperature sensor ----------

float readTemperatureC() {
  tempSensors.requestTemperatures();
  float t = tempSensors.getTempCByIndex(0);
  if (t == DEVICE_DISCONNECTED_C) {
    Serial.println("Temperature sensor disconnected!");
    return NAN;
  }
  return t;
}

// ---------- MQTT publishers ----------

void publishTelemetry(float temperatureC) {
  char topic[64];
  snprintf(topic, sizeof(topic), "boxes/%s/telemetry", BOX_ID);

  StaticJsonDocument<256> doc;
  doc["ts"] = (long)(millis() / 1000);
  doc["box_id"] = BOX_ID;
  doc["temperature"] = temperatureC;

  char payload[256];
  size_t n = serializeJson(doc, payload, sizeof(payload));
  if (!mqttClient.publish(topic, payload, n)) {
    Serial.println("Failed to publish telemetry");
  } else {
    Serial.print("Telemetry published: ");
    Serial.println(payload);
  }
}

void publishAlert(const char* reason, float temperatureC) {
  char topic[64];
  snprintf(topic, sizeof(topic), "boxes/%s/alerts", BOX_ID);

  StaticJsonDocument<256> doc;
  doc["ts"] = (long)(millis() / 1000);
  doc["box_id"] = BOX_ID;
  doc["reason"] = reason;
  doc["temperature"] = temperatureC;

  char payload[256];
  size_t n = serializeJson(doc, payload, sizeof(payload));
  if (!mqttClient.publish(topic, payload, n)) {
    Serial.println("Failed to publish alert");
  } else {
    Serial.print("Alert published: ");
    Serial.println(payload);
  }
}

void publishScan(const String& passkey) {
  char topic[64];
  snprintf(topic, sizeof(topic), "boxes/%s/scan", BOX_ID);

  StaticJsonDocument<512> doc;
  doc["ts"] = (long)(millis() / 1000);
  doc["box_id"] = BOX_ID;
  doc["passkey_string"] = passkey;  // ONLY passkey string + box_id

  char payload[512];
  size_t n = serializeJson(doc, payload, sizeof(payload));
  if (!mqttClient.publish(topic, payload, n)) {
    Serial.println("Failed to publish scan");
  } else {
    Serial.print("Scan published: ");
    Serial.println(payload);
  }
}

// ---------- Serial scan (manual) ----------

/*
 * Parse Serial input to simulate a scan.
 * Expected format:
 *   SCAN <PASSKEY_STRING>
 * (For backward compatibility, we also accept "SCAN <ORDER_ID> <PASSKEY_STRING>"
 *  but ignore the ORDER_ID and only send passkey_string.)
 */
void handleSerialScan() {
  if (!Serial.available()) return;

  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.length() == 0) return;

  if (!line.startsWith("SCAN ")) {
    Serial.println("Use: SCAN <PASSKEY_STRING>  or  SCAN <ORDER_ID> <PASSKEY_STRING>");
    return;
  }

  // Split into tokens
  int firstSpace = line.indexOf(' ');
  if (firstSpace < 0) {
    Serial.println("Invalid SCAN format");
    return;
  }

  String rest = line.substring(firstSpace + 1);
  rest.trim();

  // If there is another space, assume "ORDER_ID PASSKEY"
  int secondSpace = rest.indexOf(' ');
  String passkey;
  if (secondSpace < 0) {
    // SCAN <PASSKEY>
    passkey = rest;
  } else {
    // SCAN <ORDER_ID> <PASSKEY>
    passkey = rest.substring(secondSpace + 1);
  }
  passkey.trim();

  if (passkey.length() == 0) {
    Serial.println("Invalid SCAN arguments (empty passkey).");
    return;
  }

  publishScan(passkey);
}

// ---------- RFID handling ----------

// Convert UID to hex string and use it directly as passkey_string.
// If your old code reads block data instead, you can replace this
// with your previous "read passkey from tag" logic.
String uidToHexString(MFRC522::Uid* uid) {
  String s;
  for (byte i = 0; i < uid->size; i++) {
    if (uid->uidByte[i] < 0x10) s += "0";
    s += String(uid->uidByte[i], HEX);
  }
  s.toUpperCase();
  return s;
}

// If you have more advanced logic (e.g., reading MIFARE blocks),
// replace this function to return the correct passkey string.
String readPasskeyFromTag() {
  // For now, we treat UID hex as passkey_string.
  return uidToHexString(&mfrc522.uid);
}

void handleRfidScan() {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  String passkey = readPasskeyFromTag();
  unsigned long nowMs = millis();

  // Avoid retriggering rapidly for the same tag
  if (passkey == lastRfidValue && (nowMs - lastRfidTimeMs) < RFID_RETRIGGER_MS) {
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    return;
  }

  lastRfidValue = passkey;
  lastRfidTimeMs = nowMs;

  Serial.print("RFID tag detected, passkey_string = ");
  Serial.println(passkey);

  // NO lookup, NO order_id here. Just send passkey_string + box_id.
  publishScan(passkey);

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}

// ---------- Setup / loop ----------

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println();
  Serial.println("ESP32 Edge starting (MQTT over TLS, keys in LittleFS, RFID + DS18B20, NO lookup)...");

  if (!configureTLSFromFS()) {
    Serial.println("TLS configuration failed; check /certs files");
  }

  connectWiFi();

  // Temperature sensor init
  tempSensors.begin();
  Serial.println("DS18B20 temperature sensor initialized");

  // RFID init
  SPI.begin();
  mfrc522.PCD_Init();
  Serial.println("MFRC522 RFID reader initialized");

  mqttClient.setServer(MQTT_HOST, MQTT_PORT);
  connectMQTT();

  lastTelemetryMs = millis();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi disconnected, reconnecting...");
    connectWiFi();
  }

  if (!mqttClient.connected()) {
    connectMQTT();
  }

  mqttClient.loop();

  unsigned long now = millis();
  if (now - lastTelemetryMs >= TELEMETRY_INTERVAL_MS) {
    lastTelemetryMs = now;
    float tC = readTemperatureC();
    publishTelemetry(tC);
    if (!isnan(tC) && (tC < TEMP_LOW_LIMIT || tC > TEMP_HIGH_LIMIT)) {
      publishAlert("temperature_out_of_range", tC);
    }
  }

  handleSerialScan();
  handleRfidScan();
}
