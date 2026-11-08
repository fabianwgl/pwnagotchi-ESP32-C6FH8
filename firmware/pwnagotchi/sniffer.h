#pragma once
#include <stdint.h>

enum AuthType : uint8_t {
  AUTH_OPEN = 0,
  AUTH_WEP,
  AUTH_WPA,
  AUTH_WPA2,
  AUTH_WPA2_3,
  AUTH_WPA3,
  AUTH_EAP,
  AUTH_UNKNOWN
};

struct ApInfo {
  uint8_t bssid[6];
  char ssid[33];
  uint8_t ssidLen;
  uint8_t channel;
  int8_t rssi;
  uint8_t auth;
  bool hidden;
  bool handshake;
  bool pmkid;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint16_t beacons;
};

struct SnifferStats {
  int apCount;
  int hsCount;
  int savedHsCount;
  int pmkidCount;
  int eapolCount;
  int targetCount;
  int drops;
  int channel;
  bool sdOk;
  bool paused;
  bool lockMode;
  bool boost;
  bool hasTarget;
  uint8_t targetBssid[6];
  char targetSsid[33];
  uint8_t targetChannel;
  int targetRssi;
  char lastSsid[33];
  int lastRssi;
  int pcapSize;
  uint32_t deauthSent;
};

const char *authName(uint8_t a);
bool isCrackableAuth(uint8_t a);

bool snifferBegin();
void snifferLoop();
void snifferSetPaused(bool paused);
void snifferSetLock(bool lock, uint8_t channel);
bool snifferToggleLock();
bool snifferSetBoost(bool on);
bool snifferSelectTarget(int index);
bool snifferSelectTargetBssid(const uint8_t *bssid);
void snifferClearCounts();
void snifferPrintAps();
void snifferPrintStatus();
void snifferPrintPcap();
void snifferDebugRaw(int index);
void snifferSelfTest();
SnifferStats snifferStats();
