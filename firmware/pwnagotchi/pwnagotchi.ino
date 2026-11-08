// esp32-pwnagotchi
//
// A small, cute WiFi companion for the Waveshare ESP32-C6-LCD-1.47.
// It listens passively, shows nearby networks on its face, and saves the
// material needed to audit WPA2-PSK networks (4-way handshakes and PMKIDs)
// to a PCAP on the microSD card.
//
// Only use this on networks you own or have explicit written permission to
// test. Boost mode sends deauthentication frames and is active interference.

#include <Arduino.h>
#include "config.h"
#include "face.h"
#include "sniffer.h"

static int lastApCount = 0;
static int lastHsCount = 0;
static int lastPmkidCount = 0;
static bool lastPaused = false;
static uint32_t lastStat = 0;
static uint32_t ledUntil = 0;

static void ledPulse(uint8_t r, uint8_t g, uint8_t b, uint16_t ms) {
  rgbLedWrite(PIN_RGB, r, g, b);
  ledUntil = millis() + ms;
}

// ---------------------------------------------------------------- button
static bool btnRaw = false;
static bool btnStable = false;
static bool btnLongFired = false;
static uint32_t btnRawT = 0;
static uint32_t btnDownT = 0;
static bool evShort = false;
static bool evLong = false;

static void pollButton() {
  uint32_t now = millis();
  bool pressed = (digitalRead(PIN_BOOT) == LOW);

  if (pressed != btnRaw) {
    btnRaw = pressed;
    btnRawT = now;
  }
  if (btnRaw != btnStable && now - btnRawT >= 30) {
    btnStable = btnRaw;
    if (btnStable) {
      btnDownT = now;
      btnLongFired = false;
    } else if (!btnLongFired) {
      evShort = true;
    }
  }
  if (btnStable && !btnLongFired && now - btnDownT >= 1000) {
    btnLongFired = true;
    evLong = true;
  }
}

// ---------------------------------------------------------------- serial commands
static char cmdBuf[96];
static size_t cmdLen = 0;

static bool ieq(const char *a, const char *b) {
  return strcasecmp(a, b) == 0;
}

static bool startsWithI(const char *a, const char *prefix) {
  size_t n = strlen(prefix);
  return strncasecmp(a, prefix, n) == 0;
}

static void trim(char *s) {
  char *p = s;
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
  if (p != s) memmove(s, p, strlen(p) + 1);
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) {
    s[--n] = 0;
  }
}

static void printHelp() {
  Serial.println("{\"t\":\"help\",\"commands\":["
                 "\"help\",\"status\",\"aps\",\"pcap\",\"pause\",\"resume\","
                 "\"hop\",\"lock <ch>\",\"target <index>\",\"raw <index>\",\"boost on|off\","
                 "\"clear\",\"selftest\",\"demo hs|pmkid|happy|sleep\",\"reboot\"]}");
}

static void handleCommand(char *line) {
  trim(line);
  if (!line[0]) return;

  if (ieq(line, "help")) {
    printHelp();
  } else if (ieq(line, "status")) {
    snifferPrintStatus();
  } else if (ieq(line, "aps")) {
    snifferPrintAps();
  } else if (ieq(line, "pcap")) {
    snifferPrintPcap();
  } else if (ieq(line, "pause")) {
    snifferSetPaused(true);
  } else if (ieq(line, "resume")) {
    snifferSetPaused(false);
  } else if (ieq(line, "hop")) {
    snifferSetLock(false, 0);
  } else if (startsWithI(line, "lock ")) {
    int ch = atoi(line + 5);
    if (ch >= 1 && ch <= 13) {
      snifferSetLock(true, (uint8_t)ch);
    } else {
      Serial.println("{\"t\":\"error\",\"msg\":\"channel 1..13\"}");
    }
  } else if (startsWithI(line, "target ")) {
    int idx = atoi(line + 7);
    snifferSelectTarget(idx);
  } else if (startsWithI(line, "raw ")) {
    int idx = atoi(line + 4);
    snifferDebugRaw(idx);
  } else if (ieq(line, "boost on")) {
    snifferSetBoost(true);
  } else if (ieq(line, "boost off")) {
    snifferSetBoost(false);
  } else if (ieq(line, "clear")) {
    snifferClearCounts();
  } else if (ieq(line, "demo hs")) {
    faceSetMood(MOOD_EXCITED, "gotcha!", 5000);
    Serial.println("{\"t\":\"demo\",\"mood\":\"excited\"}");
  } else if (ieq(line, "demo pmkid")) {
    faceSetMood(MOOD_LOVE, "PMKID!!", 6000);
    Serial.println("{\"t\":\"demo\",\"mood\":\"love\"}");
  } else if (ieq(line, "demo happy")) {
    faceSetMood(MOOD_HAPPY, "new friend!", 3000);
    Serial.println("{\"t\":\"demo\",\"mood\":\"happy\"}");
  } else if (ieq(line, "demo sleep")) {
    faceSetMood(MOOD_SLEEP, "zzz...", 3000);
    Serial.println("{\"t\":\"demo\",\"mood\":\"sleep\"}");
  } else if (ieq(line, "selftest")) {
    snifferSelfTest();
  } else if (ieq(line, "reboot")) {
    Serial.println("{\"t\":\"reboot\"}");
    Serial.flush();
    delay(100);
    ESP.restart();
  } else {
    Serial.printf("{\"t\":\"error\",\"msg\":\"unknown command: %s\"}\n", line);
  }
}

static void pollSerial() {
  while (Serial.available()) {
    int c = Serial.read();
    if (c < 0) break;
    if (c == '\n') {
      cmdBuf[cmdLen] = 0;
      handleCommand(cmdBuf);
      cmdLen = 0;
    } else if (c != '\r') {
      if (cmdLen + 1 < sizeof(cmdBuf)) {
        cmdBuf[cmdLen++] = (char)c;
      } else {
        cmdLen = 0;
        Serial.println("{\"t\":\"error\",\"msg\":\"line too long\"}");
      }
    }
  }
}

// ---------------------------------------------------------------- setup / loop
void setup() {
  Serial.setTxBufferSize(8192);
  Serial.begin(115200);
  delay(150);

  Serial.println();
  Serial.println("{\"t\":\"boot\",\"name\":\"esp32-pwnagotchi\",\"board\":\"waveshare-c6-lcd-1.47\"}");

  pinMode(PIN_BOOT, INPUT_PULLUP);
  pinMode(PIN_RGB, OUTPUT);
  rgbLedWrite(PIN_RGB, 0, 0, 0);

  faceBegin();
  snifferBegin();

  faceSetMood(MOOD_SCAN, "sniffing...", 0);
  printHelp();

  lastStat = millis();
}

void loop() {
  snifferLoop();

  pollButton();
  pollSerial();

  SnifferStats s = snifferStats();

  if (evShort) {
    evShort = false;
    snifferToggleLock();
  }
  if (evLong) {
    evLong = false;
    snifferSetPaused(!s.paused);
  }

  if (s.paused != lastPaused) {
    lastPaused = s.paused;
    if (s.paused) {
      faceSetMood(MOOD_SLEEP, "zzz...", 0);
    } else {
      faceSetMood(MOOD_SCAN, "sniffing...", 0);
    }
  }

  if (s.pmkidCount > lastPmkidCount) {
    faceSetMood(MOOD_LOVE, "PMKID!!", 6000);
    ledPulse(32, 0, 24, 2500);
  } else if (s.hsCount > lastHsCount) {
    faceSetMood(MOOD_EXCITED, "gotcha!", 5000);
    ledPulse(32, 24, 0, 1800);
  } else if (s.apCount > lastApCount) {
    faceSetMood(MOOD_HAPPY, "new friend!", 1600);
    ledPulse(0, 32, 12, 400);
  }

  lastApCount = s.apCount;
  lastHsCount = s.hsCount;
  lastPmkidCount = s.pmkidCount;

  if (ledUntil && millis() > ledUntil) {
    rgbLedWrite(PIN_RGB, 0, 0, 0);
    ledUntil = 0;
  }

  FaceState fs = {};
  fs.apCount = s.apCount;
  fs.hsCount = s.hsCount;
  fs.savedHsCount = s.savedHsCount;
  fs.pmkidCount = s.pmkidCount;
  fs.targetCount = s.targetCount;
  fs.channel = s.channel;
  fs.rssi = s.lastRssi;
  strlcpy(fs.ssid, s.lastSsid, sizeof(fs.ssid));
  fs.sdOk = s.sdOk;
  fs.paused = s.paused;
  fs.lockMode = s.lockMode;
  fs.boost = s.boost;
  fs.pcapSize = s.pcapSize;

  faceTick(fs);

  if (millis() - lastStat >= 2000) {
    lastStat = millis();
    snifferPrintStatus();
  }

  delay(5);
}
