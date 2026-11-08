#pragma once
#include <stdint.h>

enum FaceMood : uint8_t {
  MOOD_SCAN = 0,
  MOOD_HAPPY,
  MOOD_EXCITED,
  MOOD_LOVE,
  MOOD_SLEEP,
  MOOD_IDLE
};

struct FaceState {
  int apCount;
  int hsCount;
  int savedHsCount;
  int pmkidCount;
  int targetCount;
  int channel;
  int rssi;
  char ssid[33];
  bool sdOk;
  bool paused;
  bool lockMode;
  bool boost;
  int pcapSize;
};

bool faceBegin();
void faceSetMood(FaceMood mood, const char *message, uint32_t durationMs);
void faceTick(const FaceState &s);
