/*
 * esp_edge.ino (PATCHED - supports full passkey JSON object)
 *
 * ESP32 edge node:
 *  - Connects to WiFi
 *  - Uses MQTT over TLS (port 8883) to truck Pi (Mosquitto)
 *  - Loads CA, client cert, and key from LittleFS
 *
 * MQTT topics:
 *   boxes/<BOX_ID>/telemetry   -- periodic temperature + metadata
 *   boxes/<BOX_ID>/alerts      -- temp out of range, etc.
 *   boxes/<BOX_ID>/scan        -- passkey scans (FULL JSON OBJECT)
 *
 * DESIGN:
 *   - Box sends COMPLETE passkey JSON object:
 *        {
 *          "order_id": "...",
 *          "role": "sender|receiver",
 *          "passkey_string": "...",
 *          "created_timestamp": "...",
 *          "expires_at": "...",
 *          "box_id": "<BOX_ID>",
 *          "ts": <device timestamp>
 *        }
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

const char* WIFI_SSID     = "SSID_GOES_HERE";
const char* WIFI_PASSWORD = "PASSWORD_GOES_HERE";

// For POC, use the Pi's LAN IP directly
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

// Temperature alert thresholds
const float TEMP_LOW_LIMIT  = 2.0f;
const float TEMP_HIGH_LIMIT = 8.0f;

// RFID (MFRC522) pin mapping for ESP32
#define RFID_SS_PIN  5    // SDA / SS
#define RFID_RST_PIN 27   // RST
MFRC522 mfrc522(RFID_SS_PIN, RFID_RST_PIN);

// -------------------------------------------

WiFiClientSecure secureClient;
PubSubClient mqttClient(secureClient);

unsigned long lastTelemetryMs = 0;

// Track last seen UID
String lastRfidValue = "";
unsigned long lastRfidTimeMs = 0;
const unsigned long RFID_RETRIGGER_MS = 2000;

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
  if (!LittleFS.begin(true)) {
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
    Serial.println("Missing cert/key files");
    return false;
  }

  secureClient.setCACert(ca.c_str());
  secureClient.setCertificate(cert.c_str());
  secureClient.setPrivateKey(key.c_str());
  secureClient.setTimeout(5000);
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

void publishScanJson(const JsonObject& passkeyObj) {
  char topic[64];
  snprintf(topic, sizeof(topic), "boxes/%s/scan", BOX_ID);

  // Create a larger document to include all passkey fields + metadata
  StaticJsonDocument<1024> doc;
  
  // Add device timestamp and box_id
  doc["ts"] = (long)(millis() / 1000);
  doc["box_id"] = BOX_ID;
  
  // Copy all fields from the passkey JSON object
  doc["order_id"] = passkeyObj["order_id"];
  doc["role"] = passkeyObj["role"];
  doc["passkey_string"] = passkeyObj["passkey_string"];
  doc["created_timestamp"] = passkeyObj["created_timestamp"];
  doc["expires_at"] = passkeyObj["expires_at"];

  char payload[2048];
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
 *   SCAN <JSON_STRING>
 * 
 * Example:
 *   SCAN {"order_id":"going","role":"sender","passkey_string":"eyJ...","created_timestamp":"...","expires_at":"..."}
 */
void handleSerialScan() {
  if (!Serial.available()) return;

  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.length() == 0) return;

  if (!line.startsWith("SCAN ")) {
    Serial.println("Use: SCAN <JSON_OBJECT>");
    Serial.println("Example: SCAN {\"order_id\":\"going\",\"role\":\"sender\",\"passkey_string\":\"...\"}");
    return;
  }

  // Extract JSON part after "SCAN "
  String jsonStr = line.substring(5);
  jsonStr.trim();

  if (jsonStr.length() == 0) {
    Serial.println("Invalid SCAN format: empty JSON");
    return;
  }

  // Parse the JSON
  StaticJsonDocument<1024> doc;
  DeserializationError error = deserializeJson(doc, jsonStr);
  
  if (error) {
    Serial.print("JSON parsing failed: ");
    Serial.println(error.c_str());
    return;
  }

  // Validate required fields
  if (!doc.containsKey("passkey_string")) {
    Serial.println("Invalid JSON: missing passkey_string");
    return;
  }

  if (!doc.containsKey("order_id")) {
    Serial.println("Warning: missing order_id in passkey JSON");
  }

  if (!doc.containsKey("role")) {
    Serial.println("Warning: missing role in passkey JSON");
  }

  // Publish the complete JSON object
  publishScanJson(doc.as<JsonObject>());
}

// ---------- RFID handling ----------

String uidToHexString(MFRC522::Uid* uid) {
  String s;
  for (byte i = 0; i < uid->size; i++) {
    if (uid->uidByte[i] < 0x10) s += "0";
    s += String(uid->uidByte[i], HEX);
  }
  s.toUpperCase();
  return s;
}

// For RFID tags, you could store the full passkey JSON on the tag
// This function would need to be adapted based on your tag type
// For now, it just returns the UID as a simple passkey_string
String readPasskeyFromTag() {
  return uidToHexString(&mfrc522.uid);
}

void handleRfidScan() {
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  String uidStr = readPasskeyFromTag();
  unsigned long nowMs = millis();

  // Avoid retriggering rapidly for the same tag
  if (uidStr == lastRfidValue && (nowMs - lastRfidTimeMs) < RFID_RETRIGGER_MS) {
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    return;
  }

  lastRfidValue = uidStr;
  lastRfidTimeMs = nowMs;

  Serial.print("RFID tag detected, UID = ");
  Serial.println(uidStr);

  // For RFID, create a minimal passkey object with just the UID
  // In production, you would read the full JSON from the tag
  StaticJsonDocument<512> doc;
  doc["passkey_string"] = uidStr;
  // Note: order_id and role would need to be read from tag in production
  
  publishScanJson(doc.as<JsonObject>());

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}

// ---------- Setup / loop ----------

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println();
  Serial.println("ESP32 Edge starting (MQTT over TLS, Full Passkey JSON support)...");

  if (!configureTLSFromFS()) {
    Serial.println("TLS configuration failed; check cert files");
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
  
  Serial.println("\nReady! Use serial command:");
  Serial.println("SCAN {\"order_id\":\"going\",\"role\":\"sender\",\"passkey_string\":\"eyJ...\",\"created_timestamp\":\"...\",\"expires_at\":\"...\"}");
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