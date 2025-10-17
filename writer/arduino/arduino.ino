/*
  RFID Passkey Writer (PATCHED)
  - Writes FULL JSON or token string to MIFARE Classic 1K
  - Skips trailer blocks (safe)
  - Verifies by reading back and comparing (prefix up to first '\0')
  - Echoes status lines:
      OK:READY
      OK:CARD
      OK:WRITE <bytes>
      OK:VERIFY
      ERR:TOO_LONG <needed>/<capacity>
      ERR:AUTH <sector>
      ERR:WRITE <block>
      ERR:READBACK
      ERR:NO_CARD
*/

#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 10
#define RST_PIN 9

MFRC522 mfrc522(SS_PIN, RST_PIN);
const byte DEFAULT_KEY[6] = {0xFF,0xFF,0xFF,0xFF,0xFF};

String incoming;

struct Capacity {
  int dataBlocks;  // total data blocks writable
  int bytes;       // dataBlocks * 16
};

// For MIFARE Classic 1K: sectors 1..15, blocks per sector: 4 * 16 bytes (block 3 is trailer), so 3 data blocks/sector.
// That yields 15 * 3 = 45 blocks => 720 bytes.
Capacity getCapacityClassic1K() {
  Capacity c;
  c.dataBlocks = 15 * 3;
  c.bytes = c.dataBlocks * 16;
  return c;
}

bool authSector(byte sector, MFRC522::MIFARE_Key &key) {
  byte trailerBlock = sector * 4 + 3;
  MFRC522::StatusCode st = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  return st == MFRC522::STATUS_OK;
}

bool writeDataClassic1K(const String &s, String &err, int &writtenBytes) {
  writtenBytes = 0;
  Capacity cap = getCapacityClassic1K();

  int needed = s.length() + 1; // include terminating 0
  if (needed > cap.bytes) {
    err = String("ERR:TOO_LONG ") + needed + "/" + cap.bytes;
    return false;
  }

  MFRC522::MIFARE_Key key;
  for (byte i=0;i<6;i++) key.keyByte[i] = DEFAULT_KEY[i];

  int idx = 0;
  // Iterate sectors 1..15
  for (byte sector = 1; sector <= 15; sector++) {
    if (!authSector(sector, key)) {
      err = String("ERR:AUTH ") + sector;
      return false;
    }
    // data blocks within sector: block 0..2
    for (byte b = 0; b <= 2; b++) {
      byte blockAddr = sector * 4 + b;
      byte buf[16];
      for (int i=0; i<16; i++) {
        if (idx < s.length()) {
          buf[i] = (byte)s[idx++];
        } else if (idx == s.length()) {
          buf[i] = 0; // terminator
          idx++;
        } else {
          buf[i] = 0;
        }
      }
      MFRC522::StatusCode st = mfrc522.MIFARE_Write(blockAddr, buf, 16);
      if (st != MFRC522::STATUS_OK) {
        err = String("ERR:WRITE ") + blockAddr;
        return false;
      }
      writtenBytes += 16;
      if (idx > s.length()) {
        // fully written including terminator; zeroed remainder of this & later blocks already by loop
        return true;
      }
    }
  }
  return true;
}

bool readBackClassic1K(String &out) {
  out = "";
  MFRC522::MIFARE_Key key;
  for (byte i=0;i<6;i++) key.keyByte[i] = DEFAULT_KEY[i];

  // Read in same order, stop at 0 byte
  for (byte sector = 1; sector <= 15; sector++) {
    if (!authSector(sector, key)) return false;
    for (byte b = 0; b <= 2; b++) {
      byte blockAddr = sector * 4 + b;
      byte buf[18]; byte size = sizeof(buf);
      MFRC522::StatusCode st = mfrc522.MIFARE_Read(blockAddr, buf, &size);
      if (st != MFRC522::STATUS_OK) return false;
      for (int i=0;i<16;i++) {
        char c = (char)buf[i];
        if (c == '\0') return true;
        out += c;
      }
    }
  }
  return true;
}

void waitForCard() {
  while (!mfrc522.PICC_IsNewCardPresent()) delay(50);
  while (!mfrc522.PICC_ReadCardSerial()) delay(50);
}

void setup() {
  Serial.begin(115200);
  incoming.reserve(1024);
  SPI.begin();
  mfrc522.PCD_Init();
  Serial.println("OK:READY");
}

void loop() {
  // collect a line from serial
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      incoming.trim();
      if (incoming.length() > 0) {
        Serial.println("OK:ARMED");   // we got a line, ask for card
        Serial.println("Present card...");
        waitForCard();
        Serial.println("OK:CARD");

        String err; int written = 0;
        bool ok = writeDataClassic1K(incoming, err, written);
        if (!ok) {
          Serial.println(err);
        } else {
          Serial.print("OK:WRITE ");
          Serial.println(written);

          // verify
          String rb;
          if (!readBackClassic1K(rb)) {
            Serial.println("ERR:READBACK");
          } else {
            // Compare only up to original length (writer pads with zeros)
            if (rb.length() >= incoming.length() && rb.substring(0, incoming.length()) == incoming) {
              Serial.println("OK:VERIFY");
            } else {
              Serial.println("ERR:MISMATCH");
              Serial.print("READ:");
              Serial.println(rb);
            }
          }
        }

        // Halt/stop
        mfrc522.PICC_HaltA();
        mfrc522.PCD_StopCrypto1();
      }
      incoming = "";
    } else {
      incoming += c;
      // simple guard
      if (incoming.length() > 1200) {
        // avoid runaway; MIFARE Classic 1K realistically supports ~720 bytes data
        incoming = incoming.substring(0, 1200);
      }
    }
  }
}
