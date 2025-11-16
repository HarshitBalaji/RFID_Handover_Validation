/* esp32_box_main.ino (PATCHED for POC)
   - DS18B20 on ONE_WIRE_BUS
   - Publishes telemetry to: boxes/<box_id>/telemetry   (JSON)
   - Publishes scans to:     boxes/<box_id>/scan        (JSON: full passkey JSON if available; else token)
   - ESP32 does NOT add GPS (Truck appends GPS)
   - Telemetry interval ≈ 2 minutes (configurable)
   - Optional signing (disabled by default for POC stability)

   Libraries:
     - DallasTemperature, OneWire
     - PubSubClient
     - ArduinoJson
     - MFRC522
*/

#include <WiFi.h>
#include <LittleFS.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DallasTemperature.h>
#include <OneWire.h>
#include <time.h>
#include <SPI.h>
#include <MFRC522.h>

// ---------- POC config ----------
#define ENABLE_SIGNING   0     // 0 = disable signing (recommended for POC); 1 = enable mbedTLS signing
#define TELEM_MS         120000UL  // ~2 minutes
#define ONE_WIRE_BUS     25

// RC522 pins
#define RST_PIN          22
#define SS_PIN           21  // SDA/SS

// WiFi / MQTT (set these)
const char* ssid        = "Balaji.2007@74";
const char* password    = "172411@1234";
const char* mqtt_server = "192.168.29.189";
const int   mqtt_port   = 1883;

// IMPORTANT: box_id = device_id for topic naming. Change per device or load from FS.
const char* box_id      = "box-001";

// ---------- Globals ----------
WiFiClient espClient;
PubSubClient mqttClient(espClient);

OneWire oneWire(ONE_WIRE_BUS);
DallasTemperature sensors(&oneWire);

// RFID (RC522)
MFRC522 rfid(SS_PIN, RST_PIN);

// ---------- Optional signing (off by default) ----------
#if ENABLE_SIGNING
  #include <mbedtls/pk.h>
  #include <mbedtls/sha256.h>
  #include <mbedtls/ctr_drbg.h>
  #include <mbedtls/entropy.h>
  mbedtls_pk_context device_pk;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;

  String readFileToString(const char* path) {
    if (!LittleFS.exists(path)) return "";
    File f = LittleFS.open(path, "r");
    String s;
    while (f.available()) s += (char)f.read();
    f.close();
    return s;
  }

  bool init_signing() {
    mbedtls_pk_init(&device_pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    const char *pers = "esp32_sign";
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char*)pers, strlen(pers)) != 0) {
      Serial.println("ctr_drbg_seed failed");
      return false;
    }
    String pem = readFileToString("/esp_priv.pem");
    if (pem.length() == 0) {
      Serial.println("Missing /esp_priv.pem");
      return false;
    }
    int rc = mbedtls_pk_parse_key(&device_pk,
                                  (const unsigned char*)pem.c_str(),
                                  pem.length() + 1,
                                  NULL, 0,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
      Serial.printf("pk_parse_key failed: %d\n", rc);
      return false;
    }
    return true;
  }

  // Simple base64 (RFC 4648)
  String base64_encode(const unsigned char* data, size_t len) {
    const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    String out;
    size_t i = 0;
    while (i + 3 <= len) {
      uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i+1] << 8) | ((uint32_t)data[i+2]);
      out += b64[(v >> 18) & 0x3F];
      out += b64[(v >> 12) & 0x3F];
      out += b64[(v >> 6) & 0x3F];
      out += b64[v & 0x3F];
      i += 3;
    }
    if (i < len) {
      int rem = len - i;
      uint32_t v = ((uint32_t)data[i] << 16) | (rem > 1 ? ((uint32_t)data[i+1] << 8) : 0);
      out += b64[(v >> 18) & 0x3F];
      out += b64[(v >> 12) & 0x3F];
      if (rem == 2) out += b64[(v >> 6) & 0x3F]; else out += '=';
      out += '=';
    }
    return out;
  }

  String sign_payload_and_wrap(const String& payload_json) {
    // Hash
    unsigned char hash[32];
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, (const unsigned char*)payload_json.c_str(), payload_json.length());
    mbedtls_sha256_finish(&sha, hash);
    mbedtls_sha256_free(&sha);

    // Sign (mbedTLS v3 API: needs sig buffer size and hash length)
    unsigned char sig[128];
    size_t sig_len = 0;
    int rc = mbedtls_pk_sign(&device_pk,
                             MBEDTLS_MD_SHA256,
                             hash,
                             sizeof(hash),         // <-- hash length (32)
                             sig,
                             sizeof(sig),          // <-- sig buffer size
                             &sig_len,
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);
    if (rc != 0) {
      Serial.printf("mbedtls_pk_sign failed: %d\n", rc);
      return String();
    }
    String sig_b64 = base64_encode(sig, sig_len);

    // Wrap
    StaticJsonDocument<512> doc;
    doc["device_id"] = box_id;
    doc["ts"] = (int)time(nullptr);
    doc["payload_canonical"] = payload_json;  // for verification elsewhere
    doc["signature_b64"] = sig_b64;
    String out;
    serializeJson(doc, out);
    return out;
  }
#endif

// ---------- Helpers ----------
bool mqtt_connect() {
  while (!mqttClient.connected()) {
    Serial.print("MQTT...");
    if (mqttClient.connect(box_id)) {
      Serial.println("ok");
      return true;
    } else {
      Serial.print("fail rc=");
      Serial.println(mqttClient.state());
      delay(2000);
    }
  }
  return true;
}

String make_telem_payload(float tempC, int ts) {
  // Minimal JSON the Truck expects; Truck appends order_id/GPS
  StaticJsonDocument<256> doc;
  doc["device_id"] = box_id;
  doc["ts"] = ts;
  JsonObject p = doc.createNestedObject("payload");
  p["temperature"] = tempC;
  String out; serializeJson(doc, out);
  return out;
}

// Read tag (MIFARE Classic) into a string; returns true if any bytes read
bool read_tag_string(String& out) {
  out = "";
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

  // Read a reasonable range of data blocks (skip trailer blocks)
  // Blocks 4..62 (sectors 1..15), skipping trailer every 4th block
  for (byte block = 4; block <= 62; block++) {
    if ((block % 4) == 3) continue; // trailer block
    if (rfid.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &rfid.uid) != MFRC522::STATUS_OK) {
      // stop reading further if auth fails mid-way
      break;
    }
    byte buf[18]; byte size = sizeof(buf);
    if (rfid.MIFARE_Read(block, buf, &size) != MFRC522::STATUS_OK) break;
    for (int i = 0; i < 16; i++) {
      char c = (char)buf[i];
      if (c == '\0') { return true; }
      out += c;
    }
  }
  return out.length() > 0;
}

void publish_scan_payload(const String& jsonOrToken) {
  String topic = String("boxes/") + box_id + "/scan";
  // Try to detect if jsonOrToken is JSON; if not, wrap as token
  StaticJsonDocument<512> tmp;
  DeserializationError err = deserializeJson(tmp, jsonOrToken);
  String out;
  if (!err && tmp.is<JsonObject>()) {
    // Already full JSON from tag (ideal case)
    serializeJson(tmp, out);
  } else {
    // Token-only fallback
    StaticJsonDocument<256> doc;
    doc["passkey_string"] = jsonOrToken;
    serializeJson(doc, out);
  }
  mqttClient.publish(topic.c_str(), out.c_str(), true);
  Serial.printf("Published scan (%u bytes) to %s\n", out.length(), topic.c_str());
}

// ---------- Setup / Loop ----------
unsigned long lastTelem = 0;

void setup() {
  Serial.begin(115200);
  delay(300);

  // Filesystem
  if (!LittleFS.begin()) {
    Serial.println("LittleFS mount failed (ok for POC if not signing)");
  } else {
    Serial.println("LittleFS mounted");
  }

#if ENABLE_SIGNING
  if (!init_signing()) {
    Serial.println("Signing init failed (continuing without signing)");
  } else {
    Serial.println("Signing ready");
  }
#endif

  // Sensors
  sensors.begin();

  // WiFi
  WiFi.begin(ssid, password);
  Serial.print("WiFi");
  while (WiFi.status() != WL_CONNECTED) { Serial.print("."); delay(300); }
  Serial.println(" connected");

  // MQTT
  mqttClient.setServer(mqtt_server, mqtt_port);
  mqtt_connect();

  // Time (for ts)
  configTime(0, 0, "pool.ntp.org", "time.google.com");

  // RFID
  SPI.begin();       // default HSPI pins: SCK=18, MISO=19, MOSI=23
  rfid.PCD_Init();
  Serial.println("RFID ready");
}

void loop() {
  if (!mqttClient.connected()) mqtt_connect();
  mqttClient.loop();

  // Telemetry every TELEM_MS
  if (millis() - lastTelem >= TELEM_MS) {
    sensors.requestTemperatures();
    float temp = sensors.getTempCByIndex(0);
    int ts = (int)time(nullptr);

    // Build payload (no GPS). If signing enabled, wrap signed; else raw JSON.
    String payload = make_telem_payload(temp, ts);
#if ENABLE_SIGNING
    String signed_wrap = sign_payload_and_wrap(payload);
    if (signed_wrap.length() > 0) {
      String topic = String("boxes/") + box_id + "/telemetry";
      mqttClient.publish(topic.c_str(), signed_wrap.c_str(), true);
      Serial.printf("Telemetry (signed) %.2fC @ %d\n", temp, ts);
    } else {
      Serial.println("Telemetry signing failed; skipping publish");
    }
#else
    String topic = String("boxes/") + box_id + "/telemetry";
    mqttClient.publish(topic.c_str(), payload.c_str(), true);
    Serial.printf("Telemetry %.2fC @ %d\n", temp, ts);
#endif
    lastTelem = millis();
  }

  // RFID: detect & read; publish full JSON if present
  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String tagContent;
    bool ok = read_tag_string(tagContent);
    if (ok && tagContent.length() > 0) {
      Serial.println("Tag read:");
      Serial.println(tagContent);
      publish_scan_payload(tagContent);
    } else {
      Serial.println("Tag read: empty or failed");
    }
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    delay(400); // debounce
  }
}
