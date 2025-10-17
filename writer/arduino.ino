#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 10
#define RST_PIN 9

MFRC522 mfrc522(SS_PIN, RST_PIN);

byte defaultKey[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

String incoming = "";

void setup() {
  Serial.begin(115200);
  SPI.begin();
  mfrc522.PCD_Init();
  Serial.println("RFID writer ready. Send passkey JSON line over serial.");
}

void writeStringToTag(String s) {
  // Convert to bytes
  int totalLen = s.length();
  // We'll write into MIFARE Classic blocks 4..15 (12 blocks * 16 = 192 bytes)
  byte buffer[16];
  int idx = 0;
  for (byte block = 4; block < 16; block++) {
    // auth
    MFRC522::MIFARE_Key key;
    for (int i=0;i<6;i++) key.keyByte[i] = defaultKey[i];
    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
      Serial.print("Auth failed for block "); Serial.println(block);
      return;
    }
    // fill buffer
    for (int i=0;i<16;i++) {
      if (idx < totalLen) buffer[i] = (byte)s[idx++];
      else buffer[i] = 0;
    }
    // write
    status = mfrc522.MIFARE_Write(block, buffer, 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print("Write failed for block "); Serial.println(block);
      return;
    }
    if (idx >= totalLen) break;
  }
  Serial.println("Write complete.");
}

void loop() {
  // Read serial line
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      incoming.trim();
      if (incoming.length() > 0) {
        Serial.print("Got passkey to write: "); Serial.println(incoming);
        Serial.println("Now present a tag...");
        // Wait for a tag to present
        while (!mfrc522.PICC_IsNewCardPresent()) delay(50);
        if (!mfrc522.PICC_ReadCardSerial()) {
          Serial.println("Failed to read card serial");
        } else {
          Serial.println("Card ready. Writing...");
          writeStringToTag(incoming);
          mfrc522.PICC_HaltA();
          mfrc522.PCD_StopCrypto1();
        }
      }
      incoming = "";
    } else {
      incoming += c;
    }
  }
}
