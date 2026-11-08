#include "face.h"
#include "config.h"

#include <Arduino.h>
#include <Arduino_GFX_Library.h>

#include "face_assets.h"

// ---------------------------------------------------------------- display
// Native panel is 172x320. Rotation 1 makes the UI 320x172 landscape.
static Arduino_DataBus *bus = new Arduino_HWSPI(
    PIN_LCD_DC, PIN_LCD_CS, PIN_LCD_SCLK, PIN_LCD_MOSI, PIN_LCD_MISO, &SPI, true);
static Arduino_GFX *gfx = new Arduino_ST7789(
    bus, PIN_LCD_RST, DISPLAY_ROTATION, true /* ips */,
    172, 320, 34, 0, 34, 0);

// ---------------------------------------------------------------- layout
static const int FACE_X = 6;
static const int FACE_Y = 36;
static const int FACE_W = 170;
static const int FACE_H = 58;

static const int STATUS_X = 180;
static const int STATUS_Y = 40;
static const int STATUS_MAX = 11;

static const int TOP_H = 12;
static const int TOP_LINE_Y = 13;
static const int MID_Y = 94;
static const int MID_H = 48;
static const int BOTTOM_LINE_Y = 145;
static const int BOTTOM_Y = 150;

// ---------------------------------------------------------------- state
static bool g_faceReady = false;
static FaceMood g_mood = MOOD_SCAN;
static char g_message[40] = "sniffing...";
static uint32_t g_moodUntil = 0;

static bool g_lookRight = true;
static uint32_t g_nextLook = 0;
static const FaceBitmap *g_lastFace = nullptr;
static FaceMood g_lastMood = (FaceMood)255;
static char g_lastMessage[40] = "";

static uint32_t g_lastTop = 0;
static uint32_t g_lastStats = 0;
static uint32_t g_lastCursor = 0;
static bool g_cursorOn = true;

// ---------------------------------------------------------------- helpers
static void safeCopy(char *dst, size_t n, const char *src) {
  size_t j = 0;
  for (size_t i = 0; src && src[i] && j + 1 < n; i++) {
    uint8_t c = (uint8_t)src[i];
    dst[j++] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
  }
  dst[j] = 0;
}

static void drawFaceBitmap(const FaceBitmap &bmp, int x0, int y0) {
  int rowBytes = (bmp.w + 7) / 8;
  for (int row = 0; row < bmp.h; row++) {
    const uint8_t *p = bmp.data + row * rowBytes;
    int col = 0;
    while (col < bmp.w) {
      uint8_t b = pgm_read_byte(p + (col >> 3));
      if (b & (0x80 >> (col & 7))) {
        int start = col;
        while (col < bmp.w) {
          uint8_t bb = pgm_read_byte(p + (col >> 3));
          if (!(bb & (0x80 >> (col & 7)))) break;
          col++;
        }
        gfx->drawFastHLine(x0 + start, y0 + row, col - start, C_FG);
      } else {
        col++;
      }
    }
  }
}

static const FaceBitmap *faceForMood(FaceMood mood, bool lookRight) {
  switch (mood) {
    case MOOD_HAPPY: return &FACE_TABLE[FACE_ID_HAPPY];
    case MOOD_EXCITED: return &FACE_TABLE[FACE_ID_EXCITED];
    case MOOD_LOVE: return &FACE_TABLE[FACE_ID_FRIEND];
    case MOOD_SLEEP: return &FACE_TABLE[FACE_ID_SLEEP];
    case MOOD_IDLE: return &FACE_TABLE[FACE_ID_BORED];
    case MOOD_SCAN:
    default: return &FACE_TABLE[lookRight ? FACE_ID_LOOK_R : FACE_ID_LOOK_L];
  }
}

static void drawFace(const FaceBitmap &bmp) {
  gfx->fillRect(FACE_X, FACE_Y, FACE_W, FACE_H, C_BG);
  drawFaceBitmap(bmp, FACE_X, FACE_Y);
}

static void drawStatus(const char *text) {
  gfx->fillRect(STATUS_X, STATUS_Y - 2, LCD_W - STATUS_X, 54, C_BG);
  char buf[STATUS_MAX + 1];
  snprintf(buf, sizeof(buf), "%.*s", STATUS_MAX, text);
  gfx->setTextSize(2);
  gfx->setTextColor(C_FG, C_BG);
  gfx->setCursor(STATUS_X, STATUS_Y);
  gfx->print(buf);
}

static void drawTopBar(const FaceState &s) {
  gfx->fillRect(0, 0, LCD_W, TOP_H, C_BG);
  gfx->setTextSize(1);

  char buf[32];
  gfx->setTextColor(C_FG, C_BG);
  snprintf(buf, sizeof(buf), "CH %02d", s.channel);
  gfx->setCursor(4, 3);
  gfx->print(buf);

  snprintf(buf, sizeof(buf), "APS %d", s.apCount);
  gfx->setCursor(44, 3);
  gfx->print(buf);

  uint32_t up = millis() / 1000;
  snprintf(buf, sizeof(buf), "UP %lu:%02lu:%02lu",
           (unsigned long)(up / 3600),
           (unsigned long)((up / 60) % 60),
           (unsigned long)(up % 60));
  gfx->setCursor(96, 3);
  gfx->print(buf);

  gfx->setTextColor(s.sdOk ? C_FG : C_MUTED, C_BG);
  gfx->setCursor(296, 3);
  gfx->print(s.sdOk ? "SD" : "--");
}

static void drawBars(int rssi, int x, int y) {
  const int bars = 4;
  const int bw = 8;
  const int gap = 4;
  const int maxH = 16;

  int active = 0;
  if (rssi < 0) {
    if (rssi >= -67) active = 4;
    else if (rssi >= -75) active = 3;
    else if (rssi >= -85) active = 2;
    else active = 1;
  }

  for (int i = 0; i < bars; i++) {
    int h = 4 + i * 4;
    int bx = x + i * (bw + gap);
    int by = y + maxH - h;
    if (i < active) gfx->fillRect(bx, by, bw, h, C_FG);
    else gfx->drawRect(bx, by, bw, h, C_MUTED);
  }
}

static void drawMiddle(const FaceState &s) {
  gfx->fillRect(0, MID_Y, LCD_W, MID_H, C_BG);
  gfx->setTextSize(1);
  gfx->setTextColor(C_FG, C_BG);

  char ssid[33];
  safeCopy(ssid, sizeof(ssid), s.ssid);
  char buf[48];
  snprintf(buf, sizeof(buf), "BEST  %.20s", ssid[0] ? ssid : "<hidden>");
  gfx->setCursor(6, 96);
  gfx->print(buf);

  drawBars(s.rssi, 6, 110);
  if (s.rssi == 0) snprintf(buf, sizeof(buf), "no AP");
  else snprintf(buf, sizeof(buf), "%d dBm", s.rssi);
  gfx->setCursor(58, 116);
  gfx->print(buf);

  snprintf(buf, sizeof(buf), "TGT %d  PMKID %d", s.targetCount, s.pmkidCount);
  gfx->setCursor(180, 96);
  gfx->print(buf);

  snprintf(buf, sizeof(buf), "HS %d  SAVED %d", s.hsCount, s.savedHsCount);
  gfx->setCursor(180, 110);
  gfx->print(buf);

  if (!s.sdOk) {
    snprintf(buf, sizeof(buf), "PCAP --");
  } else if (s.pcapSize >= 1024 * 1024) {
    snprintf(buf, sizeof(buf), "PCAP %dM", s.pcapSize / (1024 * 1024));
  } else {
    snprintf(buf, sizeof(buf), "PCAP %dK", s.pcapSize / 1024);
  }
  gfx->setCursor(180, 124);
  gfx->print(buf);
}

static void drawBottom(const FaceState &s) {
  gfx->fillRect(0, BOTTOM_Y - 4, LCD_W, LCD_H - BOTTOM_Y + 4, C_BG);
  gfx->setTextSize(2);
  gfx->setTextColor(C_FG, C_BG);

  char buf[24];
  snprintf(buf, sizeof(buf), "PWND %d", s.hsCount);
  gfx->setCursor(4, BOTTOM_Y);
  gfx->print(buf);

  const char *mode = s.boost ? "BOOST" : (s.lockMode ? "LOCK" : "HOP");
  int w = (int)strlen(mode) * 12;
  gfx->setCursor(LCD_W - 4 - w, BOTTOM_Y);
  gfx->print(mode);
}

static void drawName() {
  gfx->setTextSize(2);
  gfx->setTextColor(C_FG, C_BG);
  gfx->setCursor(4, 18);
  gfx->print("pwnagotchi>");
}

static void drawCursor(bool on) {
  gfx->fillRect(138, 20, 10, 10, on ? C_FG : C_BG);
}

static void drawFrame() {
  gfx->fillScreen(C_BG);
  gfx->drawFastHLine(0, TOP_LINE_Y, LCD_W, C_FG);
  gfx->drawFastHLine(0, BOTTOM_LINE_Y, LCD_W, C_FG);
  drawName();
  drawCursor(true);
}

// ---------------------------------------------------------------- public API
bool faceBegin() {
  if (!gfx->begin(40000000)) {
    Serial.println("{\"t\":\"error\",\"msg\":\"display init failed\"}");
    return false;
  }

  pinMode(PIN_LCD_BL, OUTPUT);
  digitalWrite(PIN_LCD_BL, HIGH);

  drawFrame();

  FaceState zero = {};
  drawTopBar(zero);
  drawFace(FACE_TABLE[FACE_ID_LOOK_R]);
  drawStatus("sniffing...");
  drawMiddle(zero);
  drawBottom(zero);

  g_lastFace = &FACE_TABLE[FACE_ID_LOOK_R];
  g_lastMood = MOOD_SCAN;
  strlcpy(g_lastMessage, "sniffing...", sizeof(g_lastMessage));
  g_nextLook = millis() + 1200;
  g_lastTop = millis();
  g_lastStats = millis();
  g_lastCursor = millis();
  g_faceReady = true;

  Serial.println("{\"t\":\"face\",\"ok\":1,\"layout\":\"pwnagotchi-landscape\"}");
  return true;
}

void faceSetMood(FaceMood mood, const char *message, uint32_t durationMs) {
  if (!g_faceReady) return;
  g_mood = mood;
  if (message) {
    strlcpy(g_message, message, sizeof(g_message));
  }
  g_moodUntil = durationMs ? (millis() + durationMs) : 0;
}

void faceTick(const FaceState &s) {
  if (!g_faceReady) return;
  uint32_t now = millis();

  FaceMood mood = g_mood;
  const char *msg = g_message;
  if (s.paused) {
    mood = MOOD_SLEEP;
    msg = "zzz...";
  } else if (g_moodUntil && now > g_moodUntil) {
    mood = MOOD_SCAN;
    msg = "sniffing...";
  }

  if (mood == MOOD_SCAN && now >= g_nextLook) {
    g_lookRight = !g_lookRight;
    g_nextLook = now + 1200;
  }

  const FaceBitmap *face = faceForMood(mood, g_lookRight);
  if (!g_lastFace || face != g_lastFace || mood != g_lastMood) {
    drawFace(*face);
    g_lastFace = face;
    g_lastMood = mood;
  }

  if (strcmp(msg, g_lastMessage) != 0) {
    drawStatus(msg);
    strlcpy(g_lastMessage, msg, sizeof(g_lastMessage));
  }

  if (now - g_lastTop >= 500) {
    drawTopBar(s);
    g_lastTop = now;
  }

  if (now - g_lastCursor >= 500) {
    g_cursorOn = !g_cursorOn;
    drawCursor(g_cursorOn);
    g_lastCursor = now;
  }

  if (now - g_lastStats >= 1000) {
    drawMiddle(s);
    drawBottom(s);
    g_lastStats = now;
  }
}
