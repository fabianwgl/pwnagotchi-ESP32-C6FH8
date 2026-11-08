#pragma once
#include <stdint.h>

// Waveshare ESP32-C6-LCD-1.47
#define PIN_LCD_MOSI 6
#define PIN_LCD_SCLK 7
#define PIN_LCD_MISO 5
#define PIN_LCD_CS   14
#define PIN_LCD_DC   15
#define PIN_LCD_RST  21
#define PIN_LCD_BL   22
#define PIN_SD_CS    4
#define PIN_RGB      8
#define PIN_BOOT     9

#define LCD_W 320
#define LCD_H 172
#define DISPLAY_ROTATION 1  // 1 = landscape, 3 = landscape upside down

#define MAX_APS          64
#define MAX_HS           16
#define MAX_FRAME        640
#define PKT_QUEUE_LEN    16
#define HOP_MS           300
#define SD_RETRY_MS      30000
#define PCAP_FLUSH_MS    5000
#define DEAUTH_INTERVAL_MS 2500

static inline uint16_t rgb565(uint8_t r, uint8_t g, uint8_t b) {
  return (uint16_t)(((uint16_t)(r & 0xF8) << 8) |
                    ((uint16_t)(g & 0xFC) << 3) |
                    ((uint16_t)b >> 3));
}

// Pwnagotchi-style paper UI: near-white background, near-black ink.
#define C_BG      rgb565(250, 250, 245)
#define C_FG      rgb565(12, 12, 12)
#define C_MUTED   rgb565(90, 90, 90)
